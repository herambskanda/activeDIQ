# T-1097 QA evidence (build c85022fb5, pg16 + pg18)
Backend-only change (search API); no UI screen changed (web diff = generated schema type only), so no UI controls to click.
Independent E2E: scratch test (copy in /tmp/qa-T1097, not in source tree) drives POST /api/v1/directory/search through the real
apihost + real handler + real search.Service + real Postgres, seeded with the AC scenarios.
- e2e-TestQA_E2E_pg16.json / pg18.json (byte-identical): users listing with chips
- e2e-TestQA_E2E_names_pg*-admin.json: 3x "Priya Raman" across OUs/domains (domain present)
- e2e-TestQA_E2E_names_pg*-tech.json: OU-A technician (domain empty, no hidden manager/Finance)
