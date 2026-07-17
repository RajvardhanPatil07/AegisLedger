"""Create durable authorization, settlement, mandate, and audit state.

Revision ID: 0001_core
Revises: None
"""
from alembic import op

revision = "0001_core"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        CREATE TYPE lifecycle_state AS ENUM (
          'PROPOSED','RESERVED','SIGNED','SUBMITTED','SETTLED','DENIED','REVERTED','EXPIRED'
        );
        CREATE TABLE policy_versions (
          id uuid PRIMARY KEY,
          schema_version text NOT NULL,
          policy_hash char(66) NOT NULL UNIQUE,
          document jsonb NOT NULL,
          status text NOT NULL CHECK (status IN ('DRAFT','APPROVED','ACTIVE','RETIRED')),
          created_by text NOT NULL,
          created_at timestamptz NOT NULL DEFAULT now(),
          activated_at timestamptz
        );
        CREATE TABLE policy_approvals (
          policy_version_id uuid NOT NULL REFERENCES policy_versions(id),
          administrator_id text NOT NULL,
          approved_at timestamptz NOT NULL DEFAULT now(),
          PRIMARY KEY (policy_version_id, administrator_id)
        );
        CREATE UNIQUE INDEX one_active_policy ON policy_versions ((status)) WHERE status = 'ACTIVE';

        CREATE TABLE proposals (
          id uuid PRIMARY KEY,
          schema_version text NOT NULL,
          principal_id text NOT NULL,
          idempotency_key text NOT NULL,
          wallet char(42) NOT NULL,
          chain_id bigint NOT NULL CHECK (chain_id > 0),
          asset text NOT NULL,
          amount numeric(78,0) NOT NULL CHECK (amount > 0),
          proposal_hash char(66) NOT NULL UNIQUE,
          body jsonb NOT NULL,
          state lifecycle_state NOT NULL DEFAULT 'PROPOSED',
          state_version bigint NOT NULL DEFAULT 0,
          deadline timestamptz NOT NULL,
          created_at timestamptz NOT NULL DEFAULT now(),
          updated_at timestamptz NOT NULL DEFAULT now(),
          UNIQUE (principal_id, idempotency_key)
        );
        CREATE TABLE reservations (
          id uuid PRIMARY KEY,
          proposal_id uuid NOT NULL UNIQUE REFERENCES proposals(id),
          amount numeric(78,0) NOT NULL CHECK (amount > 0),
          status text NOT NULL CHECK (status IN ('ACTIVE','RELEASED','SETTLED')),
          created_at timestamptz NOT NULL DEFAULT now(),
          released_at timestamptz,
          settled_at timestamptz
        );
        CREATE INDEX reservation_budget_scope ON proposals
          (principal_id, wallet, chain_id, asset, created_at);

        CREATE TABLE decisions (
          id uuid PRIMARY KEY,
          proposal_id uuid NOT NULL REFERENCES proposals(id),
          policy_version_id uuid NOT NULL REFERENCES policy_versions(id),
          reservation_id uuid REFERENCES reservations(id),
          decision_nonce uuid NOT NULL UNIQUE,
          verdict text NOT NULL CHECK (verdict IN ('ALLOW','DENY')),
          reason_codes text[] NOT NULL,
          state_version bigint NOT NULL,
          token jsonb NOT NULL,
          expires_at timestamptz NOT NULL,
          created_at timestamptz NOT NULL DEFAULT now(),
          CHECK ((verdict = 'ALLOW') = (reservation_id IS NOT NULL))
        );
        CREATE TABLE transactions (
          id uuid PRIMARY KEY,
          proposal_id uuid NOT NULL UNIQUE REFERENCES proposals(id),
          decision_id uuid NOT NULL UNIQUE REFERENCES decisions(id),
          wallet char(42) NOT NULL,
          chain_id bigint NOT NULL,
          wallet_nonce numeric(78,0) NOT NULL,
          eip712_hash char(66) NOT NULL UNIQUE,
          eip1559_hash char(66) NOT NULL UNIQUE,
          signed_transaction jsonb NOT NULL,
          submitted_at timestamptz,
          created_at timestamptz NOT NULL DEFAULT now(),
          UNIQUE (wallet, chain_id, wallet_nonce)
        );
        CREATE TABLE settlements (
          id uuid PRIMARY KEY,
          transaction_id uuid NOT NULL REFERENCES transactions(id),
          block_hash char(66) NOT NULL,
          block_number bigint NOT NULL,
          transaction_index integer NOT NULL,
          success boolean NOT NULL,
          confirmations integer NOT NULL DEFAULT 0,
          canonical boolean NOT NULL DEFAULT true,
          receipt jsonb NOT NULL,
          observed_at timestamptz NOT NULL DEFAULT now(),
          UNIQUE (transaction_id, block_hash)
        );

        CREATE TABLE mandates (
          id uuid PRIMARY KEY,
          intent_hash char(66) NOT NULL,
          mandate_nonce text NOT NULL,
          principal_id text NOT NULL,
          audience text NOT NULL,
          chain_id bigint NOT NULL,
          asset text NOT NULL,
          maximum_amount numeric(78,0) NOT NULL,
          consumed_amount numeric(78,0) NOT NULL DEFAULT 0,
          revoked_at timestamptz,
          expires_at timestamptz NOT NULL,
          body jsonb NOT NULL,
          UNIQUE (principal_id, mandate_nonce)
        );
        CREATE TABLE cart_mandate_uses (
          cart_intent_hash char(66) PRIMARY KEY,
          mandate_id uuid NOT NULL REFERENCES mandates(id),
          proposal_id uuid NOT NULL UNIQUE REFERENCES proposals(id),
          consumed_at timestamptz NOT NULL DEFAULT now()
        );
        CREATE TABLE nonce_state (
          wallet char(42) NOT NULL,
          chain_id bigint NOT NULL,
          next_nonce numeric(78,0) NOT NULL,
          version bigint NOT NULL,
          updated_at timestamptz NOT NULL DEFAULT now(),
          PRIMARY KEY (wallet, chain_id)
        );

        CREATE TABLE audit_events (
          sequence bigserial PRIMARY KEY,
          event_id uuid NOT NULL UNIQUE,
          event_type text NOT NULL,
          aggregate_id uuid,
          occurred_at timestamptz NOT NULL,
          actor text NOT NULL,
          payload jsonb NOT NULL,
          previous_hash char(66) NOT NULL,
          event_hash char(66) NOT NULL UNIQUE
        );
        CREATE TABLE attestation_roots (
          id uuid PRIMARY KEY,
          first_sequence bigint NOT NULL,
          last_sequence bigint NOT NULL,
          merkle_root char(66) NOT NULL,
          event_count integer NOT NULL,
          anchor_chain_id bigint,
          anchor_tx_hash char(66),
          evidence jsonb NOT NULL,
          created_at timestamptz NOT NULL DEFAULT now(),
          UNIQUE (first_sequence, last_sequence)
        );
        CREATE TABLE attestations (
          id uuid PRIMARY KEY,
          decision_id uuid NOT NULL REFERENCES decisions(id),
          transaction_id uuid REFERENCES transactions(id),
          signer_identity text NOT NULL,
          build_measurement text NOT NULL,
          evidence jsonb NOT NULL,
          expires_at timestamptz NOT NULL,
          created_at timestamptz NOT NULL DEFAULT now()
        );

        CREATE FUNCTION reject_audit_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          RAISE EXCEPTION 'audit_events is append-only';
        END $$;
        CREATE TRIGGER audit_events_no_update
          BEFORE UPDATE OR DELETE ON audit_events
          FOR EACH ROW EXECUTE FUNCTION reject_audit_mutation();
    """)


def downgrade() -> None:
    op.execute("""
        DROP TRIGGER IF EXISTS audit_events_no_update ON audit_events;
        DROP FUNCTION IF EXISTS reject_audit_mutation;
        DROP TABLE IF EXISTS attestations, attestation_roots, audit_events, nonce_state,
          cart_mandate_uses, mandates, settlements, transactions, decisions, reservations,
          proposals, policy_approvals, policy_versions CASCADE;
        DROP TYPE IF EXISTS lifecycle_state;
    """)

