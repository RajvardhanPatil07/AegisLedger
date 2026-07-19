import json
from datetime import UTC, datetime, timedelta

import pytest

from aegisledger.audit import (
    AnchoringService,
    AnchorReceiptV1,
    AuditJournal,
    MemoryRetentionStore,
    verify_anchored_journal,
    verify_journal,
)


def populated_journal() -> AuditJournal:
    journal = AuditJournal(now=lambda: datetime(2026, 1, 1, tzinfo=UTC))
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
    replacement = AuditJournal(now=lambda: datetime(2026, 1, 1, tzinfo=UTC))
    for index in range(5):
        replacement.append("FABRICATED", "compromised-host", {"index": index})
    assert not verify_journal(replacement.events, checkpoint).valid


def test_anchor_due_after_100_events_or_five_minutes():
    now = datetime(2026, 1, 1, tzinfo=UTC)
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


class FakeAnchor:
    def __init__(self):
        self.checkpoints = []

    def anchor(self, checkpoint):
        self.checkpoints.append(checkpoint)
        return AnchorReceiptV1(
            schema_version="aegisledger.anchor_receipt.v1",
            checkpoint_id=checkpoint.checkpoint_id,
            chain_id=11155111,
            contract="0x" + "ab" * 20,
            transaction_hash="0x" + "cd" * 32,
            block_number=123,
            merkle_root=checkpoint.merkle_root,
            anchored_at=datetime(2026, 1, 1, tzinfo=UTC),
        )


def test_anchoring_service_retains_full_history_checkpoint_and_external_receipt():
    journal = populated_journal()
    store = MemoryRetentionStore()
    anchor = FakeAnchor()
    result = AnchoringService(
        store,
        anchor,
        retention=timedelta(days=365),
        now=lambda: datetime(2026, 1, 1, tzinfo=UTC),
    ).anchor(journal)

    assert verify_anchored_journal(journal.events, result.checkpoint, result.receipt).valid
    assert result.history_key in store.object_keys()
    retained = json.loads(store.read(result.history_key))
    assert len(retained["events"]) == 5

    with pytest.raises(FileExistsError):
        store.put_once(
            result.history_key,
            b"replacement",
            retain_until=datetime(2027, 1, 1, tzinfo=UTC),
        )


def test_external_anchor_detects_replaced_checkpoint():
    journal = populated_journal()
    checkpoint = journal.checkpoint()
    receipt = FakeAnchor().anchor(checkpoint)
    replaced = checkpoint.model_copy(update={"merkle_root": "0x" + "99" * 32})
    report = verify_anchored_journal(journal.events, replaced, receipt)
    assert not report.valid
    assert "external anchor root" in " ".join(report.errors)
