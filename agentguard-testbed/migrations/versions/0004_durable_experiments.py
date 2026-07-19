"""Add restart-safe experiment jobs and results.

Revision ID: 0004_durable_experiments
Revises: 0003_complete_attestations
"""

from alembic import op

revision = "0004_durable_experiments"
down_revision = "0003_complete_attestations"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE experiments (
          id uuid PRIMARY KEY,
          schema_version text NOT NULL,
          principal_id text NOT NULL,
          request jsonb NOT NULL,
          status text NOT NULL CHECK (status IN ('QUEUED','RUNNING','COMPLETED','FAILED')),
          seed text NOT NULL,
          configuration_hash char(66) NOT NULL,
          result_uri text,
          summary jsonb,
          error text,
          created_at timestamptz NOT NULL DEFAULT now(),
          updated_at timestamptz NOT NULL DEFAULT now()
        );
        CREATE INDEX experiment_active_principal
          ON experiments (principal_id,created_at)
          WHERE status IN ('QUEUED','RUNNING');
    """)


def downgrade() -> None:
    op.drop_table("experiments")
