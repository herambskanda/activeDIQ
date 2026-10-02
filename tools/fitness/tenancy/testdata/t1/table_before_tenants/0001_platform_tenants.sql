CREATE TABLE audit_seed (id int);
-- Migration 1 (ADR-0002 rule 4): tenants, and nothing before it.
CREATE TABLE tenants (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  parent_tenant_id uuid REFERENCES tenants (id),
  name text NOT NULL DEFAULT 'tenant',
  state text NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'suspended', 'deleting')),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
