---
name: extdn-lessons
description: T-1202 extended-DN control - Samba extends the ENTRY name too, opt-in per op, lenient link parser, slow bulk lab test
metadata:
  type: feedback
---

- Samba applies LDAP_SERVER_EXTENDED_DN (…529) to the entry's own DN as well as DN-syntax values (`<GUID=hex>;<SID=…>;CN=…`); `Parent()` then fails "object DN does not parse". `ad.plainDN` strips it in toEntry/Read. Windows form of the entry name is unverified (T-1331).
- The control is opt-in (`ReadOptions/SearchRequest/ScopedRequest.ExtendedDN`, set only by read.ADSource): it changes every DN value's bytes and tier0/rights code compares plain DNs. Range follow-up requests in `Read` must carry it too.
- `dn.ParseExtendedDN` requires a GUID; links can be SID-only (FSP-ish) or plain, so DnValue uses `dn.ParseLinkValue` (every part optional, malformed prefix = error, nothing derived).
- Samba creates a ForeignSecurityPrincipal from `member: <SID=S-1-5-21-…>` via Modify; it supplies GUID+SID for it.
- `TestLabScopedSearchPagesBeyondOneThousand…` takes ~13 min on a loaded box and leaves `OU=t0695p*` behind when killed; run it alone with `-timeout 30m` in the background.
