"""Make complete attestations idempotent per authorization decision.

Revision ID: 0003_complete_attestations
Revises: 0002_artifact_idempotency
"""

from alembic import op

revision = "0003_complete_attestations"
down_revision = "0002_artifact_idempotency"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_unique_constraint(
        "one_attestation_per_decision",
        "attestations",
        ["decision_id"],
    )


def downgrade() -> None:
    op.drop_constraint(
        "one_attestation_per_decision",
        "attestations",
        type_="unique",
    )
