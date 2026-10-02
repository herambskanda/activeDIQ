# QA templates

## 1. Exploratory charter (write before you start; fill as you go)

```
Charter: Explore <area, e.g. bulk group membership> with <scale tier, hostile-name CSV, 2dc lab>
         to discover <risk, e.g. silent partial failure and wrong counts>.
Time box: 15 min · Build: <short sha> · Tester: qa-verifier
Tried:
- <action> → <observation>
- …
Anomalies:
- <what, where, evidence path> → in reject note | filed T-…
Not covered (and why):
- …
```

## 2. Evidence note (the advance note)

```
QA <ticket> · build <sha> · lab <tier, seed version>
AC1 PASS — <one line>. $ curl -s -H "Authorization: Bearer $LAB_TOKEN" https://localhost:<port>/api/v1/… | jq '.items | length'
         → 3000 ; ldapsearch count on the lab → 3000
AC2 PASS — empty OU shows the empty state with the "Create user" action. factory/demos/evidence/<ticket>/ac2-empty.png
AC3 PASS — DC stopped mid-job: job ends partiallySucceeded, 412/1000 failed items listed. ac3-dc-down.png
UI: all 14 controls on Users list and User drawer clicked; keyboard, 1280/1920, dark mode OK.
Numbers traced: header count, status chips, last-logon dates (lastLogonTimestamp, lag shown).
Smoke: PASS. a11y scan: 0 serious/critical.
Exploratory (15 min): <charter one-liner>; 1 anomaly → filed T-… (outside scope).
Not verified: <Windows-only behaviour> — needs Windows lab (D-…).
```

Never paste tokens, passwords or full responses containing personal data — counts and excerpts.

## 3. Bug ticket body (`--body-file`)

```markdown
**Where:** <screen / endpoint / component> · **Build:** <sha> · **Lab:** <tier, seed version>
**Severity:** <blocker to a milestone? data loss? security? cosmetic?> · **Frequency:** always | n of m tries

### Steps to reproduce (from a clean `make lab-reset`)
1. Sign in as <lab role>.
2. …

### Expected
<what the spec or AC says, with the link>

### Actual
<what happened — exact message, wrong number, with the API response excerpt>

### Evidence
- factory/demos/evidence/<ticket>/<name>.png
- `<command>` → `<output excerpt>`

### Notes
<suspected area if obvious; related tickets; whether it reproduces on main>
```

Security bugs: tag `security-sensitive`, title describes the impact class only ("Delegation scope
not enforced on bulk reset"), no payloads in the title or summary.
