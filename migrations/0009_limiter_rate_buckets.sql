-- 0009_limiter_rate_buckets: the shared per-principal token buckets of the rate limiter (T-0274; threat
-- model §7.8 and TM-TB2-T7, ADR-0002 rule 6, DM-07). Owner: internal/platform/limiter.
--
-- Per-principal budgets (reveal, secret, bulk, write, read) must hold across every server node, so the
-- bucket lives here and not in a node's memory. `platform_rate_buckets` is a registered global table:
-- it has no tenant_id and no RLS, because the limiter runs at chain step 10 before any tenant
-- transaction exists. The tenant is part of the key text instead (class, tenant, principal), so the
-- same principal ID in two tenants never shares a bucket. Only the owning package may name the table.
--
-- Refill and take are one statement on the database clock (clock_timestamp() after the row lock, never now()), never a node's clock, and the
-- ON CONFLICT row lock makes concurrent takes on one key serial.
--
--   tokens      the bucket level as of refilled_at (fractional: refill is rate/60 per second).
--   admitted    whether the take that last wrote the row was admitted; the statement reads it back.
-- A row that has refilled to its burst carries no state and may be deleted; nothing depends on it.

CREATE TABLE public.platform_rate_buckets (
  key text PRIMARY KEY CHECK (octet_length(key) BETWEEN 1 AND 512),
  tokens double precision NOT NULL CHECK (tokens >= 0),
  admitted boolean NOT NULL,
  refilled_at timestamptz NOT NULL DEFAULT now()
);

COMMENT ON TABLE public.platform_rate_buckets IS 'Registered global table (ADR-0002 rule 6, DM-07): shared per-principal rate-limit token buckets, keyed by class, tenant and principal. Only internal/platform/limiter references it in SQL.';
