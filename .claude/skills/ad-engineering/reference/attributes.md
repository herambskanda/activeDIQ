# Key AD attributes

Syntax OIDs: `2.5.5.10` Octet String · `2.5.5.17` SID · `2.5.5.16` Large Integer (int64; FILETIME
or interval) · `2.5.5.11` Generalized Time · `2.5.5.9` Integer (int32, signed) · `2.5.5.12` Unicode
string · `2.5.5.1` DN. **Repl.** = replicated to every DC of the domain. **GC** = in the global
catalog's partial attribute set. Per-attribute pages: `https://learn.microsoft.com/en-us/windows/win32/adschema/a-<ldapdisplayname>`.
Values marked `[UNVERIFIED]` must be confirmed on a real DC before relying on them.

FILETIME = 100-ns ticks since 1601-01-01 UTC. Unix seconds = `ticks / 10^7 − 11644473600`.
Convert server-side to ISO 8601 UTC; never ship the int64 to JavaScript (exceeds 2^53).

## Identity

| Attribute | Syntax | Repl. | GC | Notes |
| --- | --- | --- | --- | --- |
| `objectGUID` | Octet String, 16 B | yes | yes | **Our identity key.** Immutable. String form swaps byte order of the first three groups (little-endian). Address objects with `<GUID=…>` as DN. Filter by escaping all 16 bytes `\xx`. |
| `objectSid` | SID | yes | yes | Binary: revision, sub-authority count, 6-byte authority (big-endian), sub-authorities (32-bit little-endian). Changes on cross-domain migration. |
| `sIDHistory` | SID, multi | yes | yes | Old SIDs after migration. Privilege-escalation vector — surface it in security reports; writing it needs special rights. |
| `distinguishedName` | DN | yes | yes | Changes on rename/move. Display only; compare parsed and normalised. |
| `cn` / `name` | Unicode | yes | yes | RDN value; `cn` ≤ 64 chars. Rename = modifyDN, not modify. |
| `sAMAccountName` | Unicode | yes | yes | Unique per domain. Users ≤ 20 chars (legacy limit). Illegal: `" / \ [ ] : ; \| = , + * ? < >`. Computers end in `$`. |
| `userPrincipalName` | Unicode | yes | yes | Uniqueness enforced forest-wide on Windows Server 2012 R2+ DCs `[UNVERIFIED]`; not guaranteed on older DCs or Samba — check before create. |
| `sAMAccountType` | Integer | yes | yes | Indexed. `805306368` user · `805306369` computer · `268435456` security group (global/universal) · `536870912` domain-local security group. Use instead of `objectClass` for filtering. |
| `objectCategory` / `objectClass` | DN / OID multi | yes | yes | `objectClass=user` also matches computers. |

## Account state

| Attribute | Syntax | Repl. | GC | Notes |
| --- | --- | --- | --- | --- |
| `userAccountControl` | Integer | yes | yes | Flags — `uac-flags.md`. Its LOCKOUT and PASSWORD_EXPIRED bits are **not** reliable. |
| `msDS-User-Account-Control-Computed` | Integer, constructed | — | — | Reliable lockout (`0x10`) and password-expired (`0x800000`). Request explicitly; cannot filter on it. |
| `msDS-UserPasswordExpiryTimeComputed` | Large Int, constructed | — | — | Expiry as FILETIME; honours fine-grained password policies. `0x7FFFFFFFFFFFFFFF` = never. |
| `accountExpires` | Large Int (FILETIME) | yes | yes | `0` **and** `0x7FFFFFFFFFFFFFFF` both mean never. ADUC "end of 31 Dec" stores 1 Jan 00:00 local, as UTC. |
| `pwdLastSet` | Large Int (FILETIME) | yes | yes | `0` = must change at next logon. Writable values: only `0` and `-1` (= now). |
| `lockoutTime` | Large Int (FILETIME) | yes | yes | Non-zero is **not** proof of lockout (expired lockouts are not cleared until next logon). Write `0` to unlock. |
| `badPwdCount` / `badPasswordTime` | Integer / Large Int | **no** | no | Per DC. Query the PDC emulator for the authoritative count. |
| `lastLogon` | Large Int | **no** | no | Per DC, exact. Max over all DCs for the true value. |
| `lastLogonTimestamp` | Large Int | yes | yes | Lags 9–14 days by design (`msDS-LogonTimeSyncInterval`, default 14). |
| `whenCreated` | Generalized Time | yes | yes | UTC. |
| `whenChanged` | Generalized Time | **no** | yes | Each DC sets its own `[UNVERIFIED]`. Do not use for cross-DC change detection. |
| `uSNCreated` / `uSNChanged` | Large Int | **no** | — | Per-DC counters; sync watermarks only with that DC's `invocationId`. |
| `adminCount` | Integer | yes | — | `1` = protected by AdminSDHolder (or was — never cleared on removal). |
| `unicodePwd` | Octet String | write-only | — | Quoted UTF-16LE over an encrypted connection. Never readable, never logged. |

## Membership and relationships

| Attribute | Syntax | Repl. | GC | Notes |
| --- | --- | --- | --- | --- |
| `member` | DN, multi, forward link | yes | universal groups only | Ranged retrieval beyond 1500. Write here, never on `memberOf`. |
| `memberOf` | DN, multi, back-link | (computed) | partial | Excludes the primary group. From a GC of another domain: universal groups only. |
| `primaryGroupID` | Integer | yes | yes | RID of the primary group (`513` Domain Users). That membership is **not** in `member`. |
| `tokenGroups` | SID multi, constructed | — | — | Transitive security groups incl. primary. **Base-scope search only.** `tokenGroupsGlobalAndUniversal` for cross-domain. |
| `groupType` | Integer (**signed**) | yes | yes | `0x2` global · `0x4` domain-local · `0x8` universal · `0x80000000` security. Global security = `-2147483646`. |
| `manager` / `directReports` | DN forward / back-link | yes | yes | Write `manager` only. |
| `managedBy` | DN | yes | yes | Not a linked pair with an automatic back-link (`managedObjects` is the back-link). |

## Security and audit

| Attribute | Syntax | Repl. | Notes |
| --- | --- | --- | --- |
| `nTSecurityDescriptor` | Octet String (SD) | yes | Read with SD-flags control `1.2.840.113556.1.4.801` (owner/group/DACL); SACL needs SeSecurityPrivilege. Parse into the typed SD model — never edit SDDL strings. |
| `msDS-ReplAttributeMetaData` / `msDS-ReplValueMetaData` | constructed XML | — | Per attribute / per link value: originating DC, time, version. When and where, never who. |
| `servicePrincipalName` | Unicode multi | yes | Kerberoasting surface on user accounts — report it. |
| `msDS-SupportedEncryptionTypes` | Integer | yes | RC4/AES posture reporting. |
| `ms-Mcs-AdmPwd` / `msLAPS-Password` / `msLAPS-EncryptedPassword` | — | yes | Legacy / Windows LAPS secrets. Reading is a privileged, audited action. Schema may be absent. |
| `isDeleted` / `isRecycled` / `lastKnownParent` / `msDS-LastKnownRDN` | — | yes | Deleted-object handling; needs show-deleted control. |

## Domain policy (on the domain head)

`maxPwdAge`, `minPwdAge`, `lockoutDuration`, `lockoutObservationWindow` are **negative** Large Int
intervals (100-ns). `lockoutThreshold`, `minPwdLength`, `pwdHistoryLength`, `pwdProperties` are
Integers. Fine-grained policies: `msDS-PasswordSettings` objects; effective policy per user via
`msDS-ResultantPSO`. `fSMORoleOwner` on the domain head names the PDC emulator.

Schema-dependent attributes (Exchange `extensionAttribute1–15`, `proxyAddresses`, LAPS) may not
exist. Read the schema at connect time and hide what is absent — never show an empty column that
looks like data.
