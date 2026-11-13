-- FIXTURE for the P2-oci proof (T-1462): a deliberately broken migration. It is never part of the
-- product's migrations/ directory; `host p2-oci -migrations <this dir>` must fail at step=migrations.
CREATE TABLE this_statement_is_not (valid sql;
