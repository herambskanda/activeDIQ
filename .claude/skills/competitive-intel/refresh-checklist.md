# Monthly competitive refresh — checklist

Work one product at a time; commit per product. Take URLs from each research file's existing
citations — do not guess vendor URLs.

## Per ManageEngine product (ADManager Plus, ADAudit Plus, ADSelfService Plus, AD360 + adjacent)

- [ ] **Release notes** — every build since the last refresh. New feature → new ID (next free in
      its section) + matrix row `[TODO]`. Changed behaviour → update the row and its source.
      Removed → `**Retired YYYY-MM-DD**`.
- [ ] **Service packs / upgrade path** — note forced sequential upgrades or breaking changes.
- [ ] **Security advisories** — new CVEs into the customer-voice file's table (ID, CVSS, builds,
      fix, date, URL). Critical/actively exploited → same-day note to `product-manager`
      and `security-architect` (sales and posture relevance).
- [ ] **Editions and list prices** — store page and licensing PDFs; record changes with old →
      new, date and URL.
- [ ] **Ratings** — Capterra, G2, Gartner Peer Insights, PeerSpot, app stores: value, count,
      date. 403 or snippet-only → `[UNVERIFIED]`.
- [ ] **Community** — vendor forum (pitstop), Reddit r/sysadmin, Spiceworks: recurring new pain
      themes only, ≤ 3 quotes, attributed.
- [ ] `sources_last_checked` bumped for re-checked sections; Changelog entry written.

## Market

- [ ] Landscape file: M&A, new entrants, major releases by other vendors (one line each, sourced).
- [ ] Regulatory changes affecting AD audit/retention (landscape §4.7).

## Outputs

- [ ] Parity matrix rows added/updated (columns 1–4 only).
- [ ] Battlecards refreshed; `sources_last_checked` bumped.
- [ ] `knowledge/business/competitive-analysis/refresh-YYYY-MM.md` written (≤ 15 lines: what
      changed, why it matters, links, tickets filed).
- [ ] Tickets for `product-manager` on every parity-affecting change; decision drafted via
      `ceo-decisions` only if a directional reaction may be needed.
- [ ] Advance the research ticket with the report path.
