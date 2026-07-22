"""Add deployment-scoped agent service credentials.

Revision ID: 0006_service_accounts
Revises: 0005_rate_limits
"""

from alembic import op

revision = "0006_service_accounts"
down_revision = "0005_rate_limits"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE service_account_credentials (
          credential_id uuid PRIMARY KEY,
          key_id uuid NOT NULL UNIQUE,
          name text NOT NULL CHECK (length(name) BETWEEN 1 AND 128),
          subject text NOT NULL CHECK (length(subject) BETWEEN 1 AND 256),
          organization_id text NOT NULL CHECK (length(organization_id) BETWEEN 1 AND 128),
          environment_id text NOT NULL CHECK (length(environment_id) BETWEEN 1 AND 128),
          permissions text[] NOT NULL CHECK (
            cardinality(permissions) > 0 AND
            permissions <@ ARRAY[
              'proposals:read',
              'proposals:write',
              'policies:simulate',
              'attestations:verify'
            ]::text[]
          ),
          token_digest char(64) NOT NULL CHECK (token_digest ~ '^[0-9a-f]{64}$'),
          created_at timestamptz NOT NULL,
          expires_at timestamptz,
          revoked_at timestamptz,
          last_used_at timestamptz,
          CHECK (expires_at IS NULL OR expires_at > created_at)
        );
        CREATE INDEX service_account_active_scope
          ON service_account_credentials (organization_id, environment_id, subject)
          WHERE revoked_at IS NULL;
    """)


def downgrade() -> None:
    op.drop_table("service_account_credentials")
