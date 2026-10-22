-- 0005_inventory_correlations: DM-20 Correlation and the customer tier0 designations of DM-16.I8.
-- Owner: internal/directory/inventory.
--
-- This migration holds what the READ API needs (T-0167): the columns of DM-20's key attributes, the
-- tier0 facts about each side that C16 and E5 are computed from, and the designation set. The writer
-- (sync and the gate evaluation of DM-20.I4/I5) is another ticket and adds no column it cannot find here.
--
-- Both tables are directory (D) tables: a directory object is referenced by
-- (tenant_id, connection_id, object_guid), never by a DN, SID or name (X3). The objectSid that a
-- correlation rests on (DM-20.I1b, I4(c)) is EVIDENCE, stored in a plain column, never a key. The
-- DM-16 object table does not exist yet, so the object references are not foreign keys. The two
-- connection references are not either: fitness-tenancy's FK probe cannot tell two keys to one parent
-- apart (it expects the named key to be the one violated), so the writer resolves both through the
-- connection registry, which never deletes a row (DM-10 L9). tier0_designations, with one, keeps its key.

CREATE TABLE public.correlations (
  tenant_id uuid NOT NULL REFERENCES public.tenants (id),
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  ad_connection_id uuid NOT NULL,
  ad_object_guid uuid NOT NULL,
  entra_connection_id uuid NOT NULL,
  entra_object_guid uuid NOT NULL,
  -- How the correlation was made (I1, I1a, I1b). 'anchor': anchor_attr and anchor_value are set,
  -- the value is the opaque bytes (a binary anchor, or the UTF-8 of a string anchor such as employeeID).
  -- 'sid': the AD objectSid in ad_sid is the match (groups, and users with no anchor).
  match text NOT NULL CHECK (match IN ('anchor', 'sid')),
  anchor_attr text NOT NULL DEFAULT '' CHECK (length(anchor_attr) <= 100),
  anchor_value bytea CHECK (anchor_value IS NULL OR length(anchor_value) BETWEEN 1 AND 1024),
  -- The AD object's binary objectSid as the Entra object's onPremisesSecurityIdentifier carried it
  -- when the gate last ran (I4(c)). Evidence only.
  ad_sid bytea CHECK (ad_sid IS NULL OR length(ad_sid) BETWEEN 8 AND 68),
  state text NOT NULL DEFAULT 'candidate' CHECK (state IN ('candidate', 'matched', 'broken', 'removed')),
  candidate_reason text NOT NULL DEFAULT '' CHECK (candidate_reason IN
    ('', 'not_synced', 'cloud_managed', 'sid_mismatch', 'domain_mismatch', 'link_unconfirmed',
     'ambiguous_anchor', 'tenant_takeover_open', 'reconfirm_required')),
  gate_checked_at timestamptz,
  eligible_since timestamptz,
  eligibility_class text NOT NULL DEFAULT '' CHECK (eligibility_class IN ('', 'install_time', 'attested', 'lapsed')),
  reconfirmed_by uuid,
  reconfirmed_at timestamptz,
  -- tier0 of each side as the server last computed it, and why (connector-contract §8.3 F2/F5):
  -- bases are the codes of threat-model §6.4. The flag and the bases agree exactly. facts_as_of is the
  -- inventory as-of of these two facts (DM-26 data_as_of), which the statement's computed_at inherits (F3).
  ad_tier0 boolean NOT NULL DEFAULT false,
  ad_tier0_bases text[] NOT NULL DEFAULT '{}',
  entra_tier0 boolean NOT NULL DEFAULT false,
  entra_tier0_bases text[] NOT NULL DEFAULT '{}',
  facts_as_of timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  CHECK (ad_connection_id <> entra_connection_id),
  CHECK ((match = 'anchor') = (anchor_value IS NOT NULL AND anchor_attr <> '')),
  CHECK (match <> 'sid' OR ad_sid IS NOT NULL),
  CHECK ((state = 'candidate') = (candidate_reason <> '')),
  CHECK ((eligible_since IS NOT NULL) = (eligibility_class <> '')),
  CHECK ((reconfirmed_by IS NOT NULL) = (reconfirmed_at IS NOT NULL)),
  CHECK (state NOT IN ('matched') OR (gate_checked_at IS NOT NULL AND eligible_since IS NOT NULL)),
  CHECK (ad_tier0 = (cardinality(ad_tier0_bases) > 0)),
  CHECK (entra_tier0 = (cardinality(entra_tier0_bases) > 0)),
  CHECK (ad_tier0_bases <@ ARRAY['C1','C2','C3','C4','C5','C6','C7','C8','C9','C10','C11','C12','C13','C14','C15','C16','designated']::text[]),
  CHECK (entra_tier0_bases <@ ARRAY['E1','E2','E3','E4','E5','designated']::text[]),
  -- A correlation that carries tier0 facts says when they were true.
  CHECK ((NOT ad_tier0 AND NOT entra_tier0) OR facts_as_of IS NOT NULL)
);

-- I2: at most one live Entra object per AD object per Entra tenant (connection).
CREATE UNIQUE INDEX correlations_live_ad ON public.correlations (tenant_id, ad_connection_id, ad_object_guid, entra_connection_id)
  WHERE state <> 'removed';
-- ... and the same from the Entra side: one live AD object per Entra object per AD connection.
CREATE UNIQUE INDEX correlations_live_entra ON public.correlations (tenant_id, entra_connection_id, entra_object_guid, ad_connection_id)
  WHERE state <> 'removed';

ALTER TABLE public.correlations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.correlations FORCE ROW LEVEL SECURITY;
CREATE POLICY correlations_tenant ON public.correlations
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

-- Removal is a state (DM-20 Lifecycle): I4(g)'s markers survive broken and removed and a re-formed
-- correlation inherits them, so a row is never deleted by the runtime role.
REVOKE DELETE ON public.correlations FROM activediq_app;

COMMENT ON TABLE public.correlations IS 'DM-20 Correlation (directory table, RLS). Only internal/directory/inventory references it in SQL. Read by every consumer through inventory.CorrelationSource.';

-- DM-16.I8: customer-designated tier0 additions (threat model §6.4, TM-D4). One row per designated
-- object of a connection; a designated group designates the objects reached through its membership at
-- read time (connector-contract §8.3 F2), so membership is not stored here.
CREATE TABLE public.tier0_designations (
  tenant_id uuid NOT NULL REFERENCES public.tenants (id),
  connection_id uuid NOT NULL,
  object_guid uuid NOT NULL,
  designated_by uuid,
  designated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, connection_id, object_guid),
  FOREIGN KEY (tenant_id, connection_id) REFERENCES public.connections (tenant_id, id)
);

ALTER TABLE public.tier0_designations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.tier0_designations FORCE ROW LEVEL SECURITY;
CREATE POLICY tier0_designations_tenant ON public.tier0_designations
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

COMMENT ON TABLE public.tier0_designations IS 'DM-16.I8 customer tier0 designations (directory table, RLS). Only internal/directory/inventory references it in SQL.';
