"""
Safety-interlock tests for the turbine model.

These run against the pure physics model (no network needed) so the safety
logic is verified deterministically and fast. Run directly:

    python -m powerplant.test_safety

or under pytest:

    pytest powerplant/test_safety.py
"""

from .turbine_model import (
    TurbineSimulator,
    TRIP_OVERSPEED,
    TRIP_OVERTEMP,
    OVERSPEED_TRIP,
    OVERTEMP_TRIP,
    SYNC_RPM,
)


def _run(sim, seconds, **cmd):
    """Advance the sim for `seconds` of simulated time with constant commands."""
    steps = int(seconds / sim.dt)
    state = sim.state
    for _ in range(steps):
        state = sim.step(
            master_run=cmd.get("master_run", True),
            throttle_cmd=cmd.get("throttle_cmd", 0),
            breaker_cmd=cmd.get("breaker_cmd", False),
            reset_cmd=cmd.get("reset_cmd", False),
            cooling_pump=cmd.get("cooling_pump", True),
        )
    return state


def test_normal_generation_powers_the_city():
    """At a safe setpoint with the breaker closed, the city gets power."""
    sim = TurbineSimulator()
    # 83% steam holds the rotor comfortably above synchronous speed.
    _run(sim, 15, throttle_cmd=83, breaker_cmd=True, cooling_pump=True)
    s = sim.state
    assert not s.tripped, "plant should run clean at a safe setpoint"
    assert s.rpm > SYNC_RPM, f"should be synchronised, rpm={s.rpm:.0f}"
    assert s.breaker_closed and s.city_supplied, "city should be energised"
    assert s.power_mw > 1.0, f"should export power, got {s.power_mw:.1f} MW"
    assert s.temp_c < OVERTEMP_TRIP, "temperature must stay in band"
    print(f"  normal: rpm={s.rpm:.0f}  temp={s.temp_c:.0f}C  "
          f"power={s.power_mw:.1f}MW  freq={s.freq_hz:.1f}Hz  city=ON")


def test_overspeed_trips_and_latches():
    """100% steam drives speed past the overspeed limit -> latched trip."""
    sim = TurbineSimulator()
    _run(sim, 20, throttle_cmd=100, breaker_cmd=False, cooling_pump=True)
    s = sim.state
    assert s.tripped, "overspeed must trip the turbine"
    assert s.trip_cause == TRIP_OVERSPEED
    assert s.power_mw == 0.0 and not s.breaker_closed, "trip must shed load"

    # Latched: asking for full steam again does nothing until acknowledged.
    _run(sim, 5, throttle_cmd=100, breaker_cmd=True)
    assert sim.state.tripped, "trip must stay latched despite run demand"
    print(f"  overspeed: tripped at ~{OVERSPEED_TRIP:.0f} rpm, "
          f"latched (rpm now {sim.state.rpm:.0f})")


def test_overtemp_trips_without_overspeed():
    """Cooling off at a sub-overspeed setpoint -> temperature trip."""
    sim = TurbineSimulator()
    # 85% keeps rpm below the overspeed limit; no cooling lets heat build.
    _run(sim, 60, throttle_cmd=85, breaker_cmd=False, cooling_pump=False)
    s = sim.state
    assert s.tripped, "loss of cooling must trip on over-temperature"
    assert s.trip_cause == TRIP_OVERTEMP, f"cause was {s.trip_cause}"
    assert s.rpm < OVERSPEED_TRIP, "this scenario must trip on heat, not speed"
    print(f"  overtemp: tripped at ~{OVERTEMP_TRIP:.0f}C "
          f"(rpm was only {s.rpm:.0f}, below overspeed)")


def test_trip_cannot_be_reset_until_safe_then_recovers():
    """A trip clears only after the plant coasts into a safe envelope."""
    sim = TurbineSimulator()
    _run(sim, 3, throttle_cmd=100)           # just enough to trip on overspeed
    assert sim.state.tripped
    assert sim.state.rpm > 1000, "rotor should still be coasting down fast"

    # Try to reset while still spinning fast -> refused.
    _run(sim, 1, throttle_cmd=0, reset_cmd=True)
    assert sim.state.tripped, "reset must be refused while unsafe"

    # Coast down with steam shut, then acknowledge -> clears.
    _run(sim, 40, throttle_cmd=0, master_run=False)
    _run(sim, 1, throttle_cmd=0, master_run=False, reset_cmd=True)
    assert not sim.state.tripped, "reset should succeed once safe"
    print(f"  reset: refused while hot/fast, accepted after coast-down "
          f"(rpm={sim.state.rpm:.0f})")


def main():
    tests = [
        test_normal_generation_powers_the_city,
        test_overspeed_trips_and_latches,
        test_overtemp_trips_without_overspeed,
        test_trip_cannot_be_reset_until_safe_then_recovers,
    ]
    print("Running turbine safety-interlock tests:")
    for t in tests:
        t()
        print(f"  PASS  {t.__name__}")
    print(f"\nAll {len(tests)} safety tests passed.")


if __name__ == "__main__":
    main()
