from datetime import datetime, timedelta, timezone

from aegisledger.audit import AuditJournal, verify_journal


def populated_journal() -> AuditJournal:
    journal = AuditJournal(now=lambda: datetime(2026, 1, 1, tzinfo=timezone.utc))
    for index in range(5):
        journal.append(
            event_type="PROPOSAL_STATE_CHANGED",
            actor="policy-service",
            payload={"index": index, "state": "RESERVED"},
        )
    return journal


def test_checkpoint_verifies_complete_ordered_history():
    journal = populated_journal()
    checkpoint = journal.checkpoint()
    report = verify_journal(journal.events, checkpoint)
    assert report.valid
    assert report.checked_events == 5


def test_verifier_detects_modification_deletion_insertion_reordering_and_truncation():
    journal = populated_journal()
    checkpoint = journal.checkpoint()

    modified = list(journal.events)
    modified[1] = modified[1].model_copy(update={"payload": {"index": 999}})
    assert not verify_journal(modified, checkpoint).valid

    deleted = list(journal.events)
    del deleted[2]
    assert not verify_journal(deleted, checkpoint).valid

    inserted = list(journal.events)
    inserted.insert(2, inserted[1])
    assert not verify_journal(inserted, checkpoint).valid

    reordered = list(journal.events)
    reordered[1], reordered[2] = reordered[2], reordered[1]
    assert not verify_journal(reordered, checkpoint).valid

    assert not verify_journal(journal.events[:-1], checkpoint).valid


def test_verifier_rejects_wholly_replaced_history_against_trusted_checkpoint():
    original = populated_journal()
    checkpoint = original.checkpoint()
    replacement = AuditJournal(now=lambda: datetime(2026, 1, 1, tzinfo=timezone.utc))
    for index in range(5):
        replacement.append("FABRICATED", "compromised-host", {"index": index})
    assert not verify_journal(replacement.events, checkpoint).valid


def test_anchor_due_after_100_events_or_five_minutes():
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    journal = AuditJournal(now=lambda: now)
    for index in range(99):
        journal.append("TEST", "runner", {"index": index})
    assert not journal.anchor_due()
    journal.append("TEST", "runner", {"index": 99})
    assert journal.anchor_due()

    later = AuditJournal(now=lambda: now)
    later.append("TEST", "runner", {"index": 0})
    later._now = lambda: now + timedelta(minutes=5)
    assert later.anchor_due()
