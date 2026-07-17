"""Task utility: defenses must not break legitimate financial flows."""

from agentwallet.tasks.suite import run_task_suite
from agentwallet.testbed import DefenseMode


def test_utility_undefended():
    assert all(o.utility == 1.0 for o in run_task_suite(DefenseMode.UNDEFENDED))


def test_utility_guard_strict():
    outcomes = run_task_suite(DefenseMode.GUARD_STRICT)
    assert all(o.utility == 1.0 for o in outcomes), {o.task: (o.utility, o.notes) for o in outcomes}


def test_utility_guard_mev():
    outcomes = run_task_suite(DefenseMode.GUARD_MEV)
    assert all(o.utility == 1.0 for o in outcomes), {o.task: (o.utility, o.notes) for o in outcomes}
