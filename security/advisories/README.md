# Security advisories: audit copies

Every published activeDIQ security advisory is kept here as `<CVE-ID>/advisory.md` (the text
published as the GitHub security advisory) and `<CVE-ID>/record.json` (the CVE JSON 5 record as
published). New advisories start from `TEMPLATE/`.

The public distribution point is <https://github.com/herambskanda/activeDIQ/security/advisories>.
Process: `knowledge/development/runbooks/security-disclosure.md` §5. The gate is `make fitness-disclosure`,
which fails unless each advisory and its record carry the same CVE ID and one CVSS v3.1 score, the
advisory went out on the day the fix shipped, and its `target_met` is honest.

Nothing about an unfixed vulnerability belongs in this directory: the repository is public.
