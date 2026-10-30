"""
Turbine + generator process model with safety interlocks.

This is deliberately decoupled from Modbus so the physics and the safety logic
can be exercised in a plain unit test (see test_safety.py). The PLC server owns
one of these and copies values in/out of the Modbus register image each tick.

Physics (simplified lumped model, fixed timestep dt):

  speed     The steam valve demand sets a *free-running* target speed. Shaft
            speed chases it with first-order inertia. When the breaker is
            closed above synchronous speed the generator loads the shaft,
            bleeding mechanical energy into electrical power -- which both
            brakes the rotor and feeds the cityscape.

  thermal   Heat in scales with valve demand and friction with speed; heat out
            is proportional to the gap above ambient and is boosted by the
            condenser cooling pump. Temperature integrates the difference.

Safety interlocks (the whole point of the exercise):

  * OVERSPEED  -- shaft speed above OVERSPEED_TRIP rev/min.
  * OVERTEMP   -- metal temperature above OVERTEMP_TRIP degC.

A trip is *latched*: it slams the steam valve shut, opens the generator
breaker, and will not clear until the operator acknowledges it AND the plant
has coasted back into a safe envelope. This mirrors a real emergency trip
(ETS) and cannot be overridden just by lowering the setpoint.
"""

from dataclasses import dataclass

# --- Plant design constants -------------------------------------------------
NOMINAL_RPM = 3000.0        # synchronous speed for a 2-pole, 50 Hz machine
SYNC_RPM = 2950.0           # minimum speed at which the breaker may close
MAX_FREE_RPM = 3600.0       # unloaded speed at 100 % steam demand
AMBIENT_C = 25.0            # ambient / cold-iron temperature

# Safety thresholds
HIGH_RPM_WARN = 3150.0      # pre-trip speed alarm
OVERSPEED_TRIP = 3300.0     # emergency overspeed trip
HIGH_TEMP_WARN = 500.0      # pre-trip temperature alarm
OVERTEMP_TRIP = 540.0       # emergency over-temperature trip

# Thresholds the plant must fall back below before a trip can be reset
RESET_RPM = 1000.0
RESET_TEMP = 450.0

# Model gains (tuned for a readable, ~real-time response)
_ACCEL = 0.9                # how fast speed chases its target (1/s)
_LOAD_BRAKE_K = 0.08        # generator braking per rpm above sync (1/s)
_POWER_K = 0.5              # MW produced per rpm above sync
_HEAT_IN_K = 35.0           # degC/s of heating at 100 % steam demand
_FRICTION_HEAT_K = 6.0      # extra heating from windage/friction at full speed
_COOL_BASE = 0.02           # natural cooling coefficient (1/s)
_COOL_PUMP = 0.06           # extra cooling when the condenser pump runs (1/s)

TRIP_NONE = 0
TRIP_OVERSPEED = 1
TRIP_OVERTEMP = 2


@dataclass
class TurbineState:
    rpm: float = 0.0
    temp_c: float = AMBIENT_C
    power_mw: float = 0.0
    freq_hz: float = 0.0
    steam_pressure_bar: float = 0.0
    breaker_closed: bool = False
    city_supplied: bool = False
    tripped: bool = False
    trip_cause: int = TRIP_NONE
    # pre-trip warnings
    warn_high_rpm: bool = False
    warn_high_temp: bool = False


class TurbineSimulator:
    """Lumped turbine/generator model advanced one fixed timestep at a time."""

    def __init__(self, dt: float = 0.1):
        self.dt = dt
        self.state = TurbineState()

    # -- operator command inputs, applied each step ------------------------
    def step(
        self,
        master_run: bool,
        throttle_cmd: float,     # 0..100 %
        breaker_cmd: bool,       # operator request to close onto the grid
        reset_cmd: bool,         # acknowledge/clear a latched trip
        cooling_pump: bool,
    ) -> TurbineState:
        s = self.state
        dt = self.dt

        # --- Trip reset ---------------------------------------------------
        # Only honoured once the machine has coasted back to a safe envelope.
        if s.tripped and reset_cmd and s.rpm < RESET_RPM and s.temp_c < RESET_TEMP:
            s.tripped = False
            s.trip_cause = TRIP_NONE

        # A latched trip forces steam shut and the breaker open regardless of
        # what the operator is asking for -- the interlock wins.
        if s.tripped:
            throttle = 0.0
            master_run = False
            breaker_cmd = False
        else:
            throttle = max(0.0, min(100.0, throttle_cmd))
            if not master_run:
                throttle = 0.0

        # --- Speed dynamics ----------------------------------------------
        free_target = (throttle / 100.0) * MAX_FREE_RPM
        s.rpm += (free_target - s.rpm) * _ACCEL * dt

        breaker_closed = bool(breaker_cmd) and s.rpm >= SYNC_RPM
        if breaker_closed and s.rpm > SYNC_RPM:
            # Generator load brakes the rotor and exports power to the city.
            over = s.rpm - SYNC_RPM
            s.rpm -= over * _LOAD_BRAKE_K * dt
            s.power_mw = over * _POWER_K
        else:
            s.power_mw = 0.0

        if s.rpm < 0.0:
            s.rpm = 0.0

        s.breaker_closed = breaker_closed
        s.city_supplied = breaker_closed and s.power_mw > 1.0

        # --- Thermal dynamics --------------------------------------------
        heat_in = (throttle / 100.0) * _HEAT_IN_K
        friction = (s.rpm / MAX_FREE_RPM) * _FRICTION_HEAT_K
        cool_coeff = _COOL_BASE + (_COOL_PUMP if cooling_pump else 0.0)
        heat_out = cool_coeff * (s.temp_c - AMBIENT_C)
        s.temp_c += (heat_in + friction - heat_out) * dt
        if s.temp_c < AMBIENT_C:
            s.temp_c = AMBIENT_C

        # --- Derived display values --------------------------------------
        # Grid frequency only means anything while synchronised to the city.
        s.freq_hz = (s.rpm / NOMINAL_RPM) * 50.0 if breaker_closed else 0.0
        s.steam_pressure_bar = (throttle / 100.0) * 120.0

        # --- Warnings & safety trips -------------------------------------
        s.warn_high_rpm = s.rpm >= HIGH_RPM_WARN
        s.warn_high_temp = s.temp_c >= HIGH_TEMP_WARN

        if not s.tripped:
            if s.rpm >= OVERSPEED_TRIP:
                self._trip(TRIP_OVERSPEED)
            elif s.temp_c >= OVERTEMP_TRIP:
                self._trip(TRIP_OVERTEMP)

        return s

    def _trip(self, cause: int) -> None:
        s = self.state
        s.tripped = True
        s.trip_cause = cause
        s.power_mw = 0.0
        s.breaker_closed = False
        s.city_supplied = False
