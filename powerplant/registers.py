"""
Modbus register map for the power-plant turbine simulator.

This is the single source of truth shared by the PLC server (which owns the
process image) and the HMI / CLI clients (which read and write it over Modbus
TCP). Keeping it in one place means the "wire contract" between the controller
and the operator stations can never drift.

Modbus organises data into four tables. We use three of them exactly the way a
real turbine controller would:

  * Holding Registers (FC 03/06/16)  -> operator *commands & setpoints* (R/W)
  * Input Registers   (FC 04)        -> measured *telemetry* (read-only)
  * Discrete Inputs   (FC 02)        -> *alarm & trip* bits (read-only)

Modbus registers are unsigned 16-bit words, so analogue values that need a
fraction are scaled to integers on the wire and converted back in engineering
units by the helpers at the bottom of this file.
"""

# --- Network defaults -------------------------------------------------------
PLC_HOST = "127.0.0.1"
PLC_PORT = 5020          # unprivileged Modbus TCP port (standard is 502)
UNIT_ID = 1              # Modbus unit / slave id of the turbine controller

# --- Holding registers: operator commands & setpoints (read/write) ----------
HR_MASTER_RUN = 0        # 0 = stop/standby, 1 = run (admit steam)
HR_THROTTLE = 1          # steam admission valve demand, 0..100 (%)
HR_BREAKER_CLOSE = 2     # 0 = breaker open, 1 = close onto the city grid
HR_RESET_TRIP = 3        # write 1 to acknowledge & clear a latched trip
HR_COOLING_PUMP = 4      # 0 = off, 1 = on (boosts condenser cooling)

HR_COUNT = 8             # size of the holding-register block

# --- Input registers: measured telemetry (read-only) ------------------------
IR_RPM = 0               # shaft speed (rev/min)
IR_TEMP = 1              # turbine metal temperature, deci-degC  (x10)
IR_POWER = 2             # generated power, deci-MW              (x10)
IR_CITY_SUPPLIED = 3     # 1 = the cityscape is receiving power
IR_BREAKER_STATE = 4     # 1 = generator breaker closed to grid
IR_TURBINE_STATE = 5     # see STATE_* below
IR_GRID_FREQ = 6         # grid frequency, deci-Hz               (x10)
IR_STEAM_PRESSURE = 7    # header steam pressure, deci-bar       (x10)

IR_COUNT = 8             # size of the input-register block

# Turbine state machine values (IR_TURBINE_STATE)
STATE_STOPPED = 0
STATE_RUNNING = 1
STATE_TRIPPED = 2

# --- Discrete inputs: alarms & trips (read-only) ----------------------------
DI_TRIP_ACTIVE = 0       # a safety trip is latched -> steam cut, breaker open
DI_ALARM_OVERSPEED = 1   # overspeed trip fired
DI_ALARM_OVERTEMP = 2    # over-temperature trip fired
DI_WARN_HIGH_RPM = 3     # speed above warning threshold (pre-trip)
DI_WARN_HIGH_TEMP = 4    # temperature above warning threshold (pre-trip)

DI_COUNT = 8             # size of the discrete-input block

# --- Scaling helpers --------------------------------------------------------
# Analogue telemetry is transmitted as scaled integers; convert at the edges.

def to_reg_x10(value: float) -> int:
    """Engineering float -> integer register scaled by 10, clamped to u16."""
    return max(0, min(65535, int(round(value * 10))))


def from_reg_x10(reg: int) -> float:
    """Scaled integer register -> engineering float."""
    return reg / 10.0


def to_reg_int(value: float) -> int:
    """Engineering value -> plain integer register, clamped to u16."""
    return max(0, min(65535, int(round(value))))
