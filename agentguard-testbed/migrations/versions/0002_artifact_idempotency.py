"""Make one durable decision authoritative for each proposal.

Revision ID: 0002_artifact_idempotency
Revises: 0001_core
"""

from alembic import op

revision = "0002_artifact_idempotency"
down_revision = "0001_core"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_unique_constraint("decisions_proposal_id_key", "decisions", ["proposal_id"])


def downgrade() -> None:
    op.drop_constraint("decisions_proposal_id_key", "decisions", type_="unique")
