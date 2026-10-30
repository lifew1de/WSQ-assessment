"""
Terminal HMI / engineering client for the turbine PLC.

A lightweight Modbus-client companion to the web HMI, handy for quick checks,
headless environments, and driving scripted scenarios. Two modes:

  monitor   live-refreshing telemetry dashboard in the terminal (default)
  cmd       write a single command, e.g. set the throttle, then exit

Examples:
    python -m powerplant.hmi_cli monitor
    python -m powerplant.hmi_cli cmd master_run 1
    python -m powerplant.hmi_cli cmd throttle 83
    python -m powerplant.hmi_cli cmd breaker_close 1
    python -m powerplant.hmi_cli cmd reset_trip 1
"""

import argparse
import sys
import time

from pymodbus.client import ModbusTcpClient

from . import registers as R

CMD_MAP = {
    "master_run": R.HR_MASTER_RUN,
    "throttle": R.HR_THROTTLE,
    "breaker_close": R.HR_BREAKER_CLOSE,
    "reset_trip": R.HR_RESET_TRIP,
    "cooling_pump": R.HR_COOLING_PUMP,
}

STATE_NAME = {R.STATE_STOPPED: "STOPPED",
              R.STATE_RUNNING: "RUNNING",
              R.STATE_TRIPPED: "TRIPPED"}

# ANSI colours
C_RST, C_GRN, C_AMB, C_RED, C_DIM = "\033[0m", "\033[92m", "\033[93m", "\033[91m", "\033[90m"


def _bar(value, vmax, width=28, warn=None, trip=None):
    """Render a horizontal gauge bar with warn/trip colouring."""
    frac = max(0.0, min(1.0, value / vmax))
    fill = int(frac * width)
    col = C_GRN
    if trip is not None and value >= trip:
        col = C_RED
    elif warn is not None and value >= warn:
        col = C_AMB
    return col + "█" * fill + C_DIM + "·" * (width - fill) + C_RST


def read_state(client):
    ir = client.read_input_registers(0, count=R.IR_COUNT, slave=R.UNIT_ID)
    di = client.read_discrete_inputs(0, count=R.DI_COUNT, slave=R.UNIT_ID)
    if ir.isError() or di.isError():
        return None
    return ir.registers, di.bits


def monitor(host, port):
    client = ModbusTcpClient(host, port=port, timeout=1.0)
    if not client.connect():
        print(f"Cannot connect to PLC at {host}:{port}", file=sys.stderr)
        sys.exit(1)
    try:
        print("\033[2J", end="")  # clear screen once
        while True:
            data = read_state(client)
            print("\033[H", end="")  # home cursor
            if data is None:
                print("PLC link error...        ")
                time.sleep(0.5)
                continue
            ir, di = data
            rpm = ir[R.IR_RPM]
            temp = R.from_reg_x10(ir[R.IR_TEMP])
            power = R.from_reg_x10(ir[R.IR_POWER])
            freq = R.from_reg_x10(ir[R.IR_GRID_FREQ])
            steam = R.from_reg_x10(ir[R.IR_STEAM_PRESSURE])
            st = STATE_NAME.get(ir[R.IR_TURBINE_STATE], "?")
            city = "ENERGISED" if ir[R.IR_CITY_SUPPLIED] else "dark"
            breaker = "CLOSED" if ir[R.IR_BREAKER_STATE] else "open"

            st_col = (C_RED if st == "TRIPPED" else
                      C_GRN if st == "RUNNING" else C_DIM)

            print("  CITY POWER STATION — TURBINE (Modbus/TCP)           ")
            print("  " + "-" * 52)
            print(f"  State    {st_col}{st:<10}{C_RST}  Breaker {breaker:<7} "
                  f"City {('on ' if ir[R.IR_CITY_SUPPLIED] else 'off')}   ")
            print(f"  RPM      {rpm:>5}  {_bar(rpm, 3600, warn=3150, trip=3300)} ")
            print(f"  Temp °C  {temp:>5.0f}  {_bar(temp, 600, warn=500, trip=540)} ")
            print(f"  Power MW {power:>5.1f}   Freq {freq:>4.1f} Hz   "
                  f"Steam {steam:>5.1f} bar      ")
            print("  " + "-" * 52)
            alarms = []
            if di[R.DI_TRIP_ACTIVE]:
                alarms.append(f"{C_RED}TRIP{C_RST}")
            if di[R.DI_ALARM_OVERSPEED]:
                alarms.append(f"{C_RED}OVERSPEED{C_RST}")
            if di[R.DI_ALARM_OVERTEMP]:
                alarms.append(f"{C_RED}OVERTEMP{C_RST}")
            if di[R.DI_WARN_HIGH_RPM]:
                alarms.append(f"{C_AMB}hi-rpm{C_RST}")
            if di[R.DI_WARN_HIGH_TEMP]:
                alarms.append(f"{C_AMB}hi-temp{C_RST}")
            print(f"  Alarms   {'  '.join(alarms) if alarms else C_GRN + 'all clear' + C_RST}"
                  + " " * 20)
            print(f"\n  {C_DIM}Ctrl-C to quit{C_RST}          ")
            time.sleep(0.4)
    except KeyboardInterrupt:
        print("\nbye")
    finally:
        client.close()


def send_cmd(host, port, name, value):
    if name not in CMD_MAP:
        print(f"unknown command '{name}'. choices: {', '.join(CMD_MAP)}",
              file=sys.stderr)
        sys.exit(2)
    client = ModbusTcpClient(host, port=port, timeout=1.0)
    if not client.connect():
        print(f"Cannot connect to PLC at {host}:{port}", file=sys.stderr)
        sys.exit(1)
    rr = client.write_register(CMD_MAP[name], int(value), slave=R.UNIT_ID)
    client.close()
    if rr.isError():
        print("write failed", file=sys.stderr)
        sys.exit(1)
    print(f"{name} <- {value}")


def main():
    ap = argparse.ArgumentParser(description="Turbine PLC terminal client")
    ap.add_argument("--host", default=R.PLC_HOST)
    ap.add_argument("--port", type=int, default=R.PLC_PORT)
    sub = ap.add_subparsers(dest="mode")
    sub.add_parser("monitor", help="live telemetry dashboard (default)")
    c = sub.add_parser("cmd", help="write one command and exit")
    c.add_argument("name", help=", ".join(CMD_MAP))
    c.add_argument("value", type=int)
    args = ap.parse_args()

    if args.mode == "cmd":
        send_cmd(args.host, args.port, args.name, args.value)
    else:
        monitor(args.host, args.port)


if __name__ == "__main__":
    main()
