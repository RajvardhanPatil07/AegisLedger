"""Add durable per-principal request-rate windows.

Revision ID: 0005_rate_limits
Revises: 0004_durable_experiments
"""

from alembic import op

revision = "0005_rate_limits"
down_revision = "0004_durable_experiments"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE rate_limit_windows (
          subject text PRIMARY KEY,
          window_started_at timestamptz NOT NULL,
          request_count integer NOT NULL CHECK (request_count >= 0),
          updated_at timestamptz NOT NULL DEFAULT now()
        );
    """)


def downgrade() -> None:
    op.drop_table("rate_limit_windows")
