"""
Power-plant PLC: a Modbus TCP server fronting the turbine simulator.

Think of this process as the turbine controller sitting in the plant. It:

  1. holds the Modbus process image (holding / input registers, discrete
     inputs) defined in registers.py,
  2. runs the turbine physics + safety interlocks on a fixed real-time tick,
  3. reads operator commands out of the holding registers and writes fresh
     telemetry / alarm bits back into the input registers and discrete inputs.

HMI and CLI clients connect over Modbus TCP and never talk to the physics
directly -- exactly like a real ICS, where the only contract is the register
map. Run it with:  python -m powerplant.plc_server
"""

import argparse
import asyncio
import logging

from pymodbus.datastore import (
    ModbusSequentialDataBlock,
    ModbusServerContext,
    ModbusSlaveContext,
)
from pymodbus.server import StartAsyncTcpServer

from . import registers as R
from .turbine_model import TurbineSimulator

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-7s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("plc")

TICK = 0.1  # seconds per simulation step (10 Hz)


def build_context() -> ModbusServerContext:
    """Create a zero-initialised Modbus data image for the controller."""
    slave = ModbusSlaveContext(
        di=ModbusSequentialDataBlock(0, [0] * R.DI_COUNT),
        co=ModbusSequentialDataBlock(0, [0] * 8),
        ir=ModbusSequentialDataBlock(0, [0] * R.IR_COUNT),
        hr=ModbusSequentialDataBlock(0, [0] * R.HR_COUNT),
        zero_mode=True,  # address N maps to index N in every table
    )
    # Sensible power-on defaults: stopped, valve shut, breaker open, pump on.
    slave.setValues(3, R.HR_MASTER_RUN, [0])
    slave.setValues(3, R.HR_THROTTLE, [0])
    slave.setValues(3, R.HR_BREAKER_CLOSE, [0])
    slave.setValues(3, R.HR_RESET_TRIP, [0])
    slave.setValues(3, R.HR_COOLING_PUMP, [1])
    return ModbusServerContext(slaves=slave, single=True)


class ScanCycle:
    """The controller's periodic scan: read commands, solve, write results."""

    def __init__(self, context: ModbusServerContext, sim: TurbineSimulator):
        self.ctx = context[0]          # single unit
        self.sim = sim
        self._last_state = None

    def _read_hr(self, addr: int) -> int:
        return self.ctx.getValues(3, addr, count=1)[0]

    def scan_once(self) -> None:
        # --- read operator commands from holding registers ---------------
        master_run = self._read_hr(R.HR_MASTER_RUN) != 0
        throttle = self._read_hr(R.HR_THROTTLE)
        breaker_cmd = self._read_hr(R.HR_BREAKER_CLOSE) != 0
        reset_cmd = self._read_hr(R.HR_RESET_TRIP) != 0
        cooling = self._read_hr(R.HR_COOLING_PUMP) != 0

        # --- advance the plant one tick ----------------------------------
        s = self.sim.step(master_run, throttle, breaker_cmd, reset_cmd, cooling)

        # A reset command is momentary: consume it so it fires once.
        if reset_cmd:
            self.ctx.setValues(3, R.HR_RESET_TRIP, [0])

        # --- publish telemetry into the input registers ------------------
        if s.tripped:
            turbine_state = R.STATE_TRIPPED
        elif master_run:
            turbine_state = R.STATE_RUNNING
        else:
            turbine_state = R.STATE_STOPPED

        self.ctx.setValues(4, R.IR_RPM, [R.to_reg_int(s.rpm)])
        self.ctx.setValues(4, R.IR_TEMP, [R.to_reg_x10(s.temp_c)])
        self.ctx.setValues(4, R.IR_POWER, [R.to_reg_x10(s.power_mw)])
        self.ctx.setValues(4, R.IR_CITY_SUPPLIED, [1 if s.city_supplied else 0])
        self.ctx.setValues(4, R.IR_BREAKER_STATE, [1 if s.breaker_closed else 0])
        self.ctx.setValues(4, R.IR_TURBINE_STATE, [turbine_state])
        self.ctx.setValues(4, R.IR_GRID_FREQ, [R.to_reg_x10(s.freq_hz)])
        self.ctx.setValues(4, R.IR_STEAM_PRESSURE, [R.to_reg_x10(s.steam_pressure_bar)])

        # --- publish alarm & trip bits into the discrete inputs ----------
        self.ctx.setValues(2, R.DI_TRIP_ACTIVE, [1 if s.tripped else 0])
        self.ctx.setValues(2, R.DI_ALARM_OVERSPEED,
                           [1 if s.trip_cause == 1 else 0])
        self.ctx.setValues(2, R.DI_ALARM_OVERTEMP,
                           [1 if s.trip_cause == 2 else 0])
        self.ctx.setValues(2, R.DI_WARN_HIGH_RPM, [1 if s.warn_high_rpm else 0])
        self.ctx.setValues(2, R.DI_WARN_HIGH_TEMP, [1 if s.warn_high_temp else 0])

        # --- log notable transitions -------------------------------------
        self._log_transitions(s)

    def _log_transitions(self, s) -> None:
        prev = self._last_state
        if prev is None or s.tripped != prev.tripped:
            if s.tripped:
                cause = {1: "OVERSPEED", 2: "OVERTEMP"}.get(s.trip_cause, "?")
                log.warning("!! SAFETY TRIP (%s) -- steam cut, breaker open "
                            "(rpm=%.0f temp=%.0f)", cause, s.rpm, s.temp_c)
            elif prev is not None:
                log.info("Trip reset -- plant back in service")
        if prev is None or s.city_supplied != prev.city_supplied:
            log.info("Cityscape %s", "ENERGISED" if s.city_supplied else "dark")
        # snapshot a shallow copy of the fields we compare on
        self._last_state = type(s)(**vars(s))


async def simulation_loop(cycle: ScanCycle) -> None:
    log.info("Turbine controller scan running at %.0f Hz", 1.0 / TICK)
    while True:
        cycle.scan_once()
        await asyncio.sleep(TICK)


async def run(host: str, port: int) -> None:
    context = build_context()
    cycle = ScanCycle(context, TurbineSimulator(dt=TICK))
    asyncio.create_task(simulation_loop(cycle))
    log.info("Modbus TCP server listening on %s:%d (unit %d)",
             host, port, R.UNIT_ID)
    await StartAsyncTcpServer(context=context, address=(host, port))


def main() -> None:
    ap = argparse.ArgumentParser(description="Power-plant turbine PLC (Modbus TCP server)")
    ap.add_argument("--host", default=R.PLC_HOST)
    ap.add_argument("--port", type=int, default=R.PLC_PORT)
    args = ap.parse_args()
    try:
        asyncio.run(run(args.host, args.port))
    except KeyboardInterrupt:
        log.info("Controller stopped")


if __name__ == "__main__":
    main()
