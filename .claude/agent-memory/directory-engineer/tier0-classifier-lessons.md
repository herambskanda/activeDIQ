---
name: tier0-classifier-lessons
description: AD tier0 classifier build - Samba in-chain cost, ranged member in Search, unreadable-GUID entries, lab creds from container env
metadata:
  type: feedback
---

- `memberOf:1.2.840.113556.1.4.1941:=` is a whole-domain scan (~7 s per term on a 7k-object Samba lab; OR of N terms is N x). Walk `member` with ranged Read per tier0 group instead; cost follows the tier0 groups, not the domain.
- `ad.Session.Search` does NOT follow ranges: a `member;range=0-1499` entry has no `member` key. Re-Read a group before trusting its members.
- A Search callback must not call back into the Session (mutex): collect, then resolve.
- Non-admin connector gets entries with no objectGUID for some System objects (Password Settings Container): skip in sensitive-subtree sweeps, keep strict for accounts.
- Unit forest tests missed all three of the above; the running Samba lab (docker `activediq-lab-dc-1`) found them. Lab creds: `docker inspect ... Config.Env` -> lab/.lab.env, CA via `docker cp .../lab-tls/ca.pem`.
- Entra and AD classifiers share package `tier0`; AD types carry the AD prefix.
