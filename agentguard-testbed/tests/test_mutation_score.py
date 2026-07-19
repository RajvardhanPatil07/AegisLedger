import pytest

from scripts.check_mutation_score import evaluate


def stats(**updates):
    report = {
        "killed": 96,
        "survived": 4,
        "no_tests": 0,
        "skipped": 0,
        "suspicious": 0,
        "timeout": 0,
        "check_was_interrupted_by_user": 0,
        "segfault": 0,
    }
    return {**report, **updates}


def test_accepts_score_at_or_above_threshold():
    passed, message = evaluate(stats(), 95.0)

    assert passed
    assert "96.00%" in message


def test_rejects_score_below_threshold():
    passed, message = evaluate(stats(killed=94, survived=6), 95.0)

    assert not passed
    assert "94.00%" in message


@pytest.mark.parametrize("field", ["no_tests", "skipped", "timeout", "segfault"])
def test_rejects_unresolved_mutation_results(field):
    passed, message = evaluate(stats(**{field: 1}), 95.0)

    assert not passed
    assert f"{field}=1" in message


def test_rejects_empty_or_malformed_reports():
    passed, message = evaluate(stats(killed=0, survived=0), 95.0)
    assert not passed
    assert "no assessed mutants" in message

    with pytest.raises(ValueError, match="non-negative integer"):
        evaluate(stats(killed=-1), 95.0)

    with pytest.raises(ValueError, match="between 0 and 100"):
        evaluate(stats(), 101.0)
