---
cve: "{{CVE_ID}}"
ghsa: "{{GHSA_ID}}"
advisory_url: "https://github.com/herambskanda/activeDIQ/security/advisories/{{GHSA_ID}}"
title: "{{TITLE}}"
severity: "{{SEVERITY}}"
cvss_vector: "{{CVSS_VECTOR}}"
cvss_score: {{CVSS_SCORE}}
cwe: "{{CWE_ID}}"
reported: "{{REPORTED}}"
triaged: "{{TRIAGED}}"
fix_shipped: "{{FIX_DAY}}"
published: "{{FIX_DAY}}"
fixed_in: ["{{FIXED_IN}}"]
target_met: {{TARGET_MET}}
credit: ["{{CREDIT}}"]
---
<!--
activeDIQ security advisory template (runbook knowledge/development/runbooks/security-disclosure.md §5).
Copy this directory to security/advisories/<CVE-ID>/, fill every {{PLACEHOLDER}} in both files, and run
`make fitness-disclosure`. Everything below the front matter is pasted, unchanged, as the description
of the GitHub security advisory. The front matter is our audit copy; it is not published.
Rules the gate enforces: the same CVE ID, CVSS v3.1 vector and score here and in record.json; severity is the
CVSS rating and nothing else; published = fix_shipped; target_met is honest. Delete this comment.
-->
# {{TITLE}}

| | |
| --- | --- |
| **CVE** | {{CVE_ID}} |
| **Severity** | {{SEVERITY}} — CVSS v3.1 base score {{CVSS_SCORE}} |
| **Vector** | `{{CVSS_VECTOR}}` |
| **Weakness** | {{CWE_ID}} {{CWE_NAME}} |
| **Affected** | activeDIQ {{AFFECTED}} |
| **Fixed in** | activeDIQ {{FIXED_IN}}, released {{FIX_DAY}} |
| **Exploited in the wild** | {{EXPLOITED}} |

This is the only score we publish. The CVE record carries the same vector and score.

## Who is affected

{{WHO_IS_AFFECTED}}
<!-- Name the component (server, API, console, self-service portal, connector, DC-side component,
installer, update channel) and the configuration that makes an installation vulnerable. Say plainly
if a default installation is affected. -->

## Impact

{{IMPACT}}
<!-- What an attacker needs (network position, account, role) and what they gain, in directory terms:
for example "a help-desk operator can reset passwords of protected (adminCount=1) accounts". -->

## What to do

1. Update to activeDIQ {{FIXED_IN}} or later. {{UPDATE_NOTE}}
2. {{WORKAROUND}}
<!-- A workaround or mitigation for customers who cannot update today, or "No workaround; update." -->
3. {{DETECTION}}
<!-- How to tell whether it was exploited: which activeDIQ audit events or directory changes to review. -->

## Timeline

| Date | Event |
| --- | --- |
| {{REPORTED}} | Reported to activeDIQ |
| {{TRIAGED}} | Confirmed and scored |
| {{FIX_DAY}} | Fix released and this advisory published |

{{TARGET_STATEMENT}}
<!-- Either "Fixed within our <severity> target of N days from triage." or, if target_met is false,
"We missed our N-day target by M days because …". We say so; the gate checks target_met. -->

## Credit

{{CREDIT_LINE}}
<!-- As the reporter asked, or "Found by the activeDIQ team." Credits go here, never in the CVE description. -->

## References

- {{CVE_ID}} record: <https://www.cve.org/CVERecord?id={{CVE_ID}}>
- Fix: {{FIX_COMMIT_URL}}
- activeDIQ security policy: <https://github.com/herambskanda/activeDIQ/blob/main/SECURITY.md>
