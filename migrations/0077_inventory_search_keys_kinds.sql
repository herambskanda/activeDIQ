-- 0074 (T-1129): the search key kinds of the identifiers the 2a sync set could not serve (ADR-0011 rule 9).
--   key_kind  11 mail_nickname  12 employee_id  13 sid_history  14 spn  15 org_text (title, department)
-- The BitLocker key-ID kind is not here: it is read under a permission the catalogue does not define yet.
-- The kinds are derived data like the rest of the table; the backfill writes them for existing rows.

ALTER TABLE public.inventory_search_keys DROP CONSTRAINT inventory_search_keys_key_kind_check;
ALTER TABLE public.inventory_search_keys ADD CONSTRAINT inventory_search_keys_key_kind_check CHECK (key_kind BETWEEN 1 AND 15);
