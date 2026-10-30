---
title: Threat-model [UNVERIFIED — lab] / [LAB] items checked on a Windows DC (T-0076)
status: draft
owner: ad-expert
ticket: T-0076
---
# AD-side lab confirmation (T-0076, 2026-10-28)

Target: dc1, Windows Server 2025, forest and domain level 2025, Recycle Bin enabled, LDAP signing required
(see `dc-read-paths-20261028.md`). Clients: Python `ldap3` over verified LDAPS from the Linux host (no Windows
client in the loop, so these are protocol-level facts) and PowerShell over WinRM for setup. Raw output:
`T-0076-ad-lab-confirmation-20261028.log.txt`. Throwaway objects in `OU=T0076` (removed afterwards).

| TM item | Result on Windows | Evidence |
| --- | --- | --- |
| TM-X3 default self-write | **Confirmed, and narrower than the tag implied.** `user` `defaultSecurityDescriptor` grants SELF (PS) read/write on property sets Personal-Information `77b5b886-…`, Email-Information `e45795b2-…` and Web-Information `e45795b3-…`. As a plain user: `telephoneNumber mobile l info homePhone wWWHomePage url msDS-cloudExtensionAttribute1 msDS-SupportedEncryptionTypes msDS-ExternalDirectoryObjectId` **written**; `description mail displayName homeDirectory profilePath scriptPath userPrincipalName proxyAddresses manager department title company givenName sAMAccountName userAccountControl servicePrincipalName adminCount msDS-AllowedToDelegateTo` **denied (50)**. So `homeDirectory`/`profilePath` UNC coercion is not a default self-write; it needs an estate delegation. Note the two self-writable security-relevant attributes below | log t1; schema read in p1, p2 |
| TM-X3 side effects | `msDS-SupportedEncryptionTypes` (Personal-Information) is self-writable: a user can change the etypes advertised for their own account. `msDS-ExternalDirectoryObjectId` is self-writable too: a user can write the Entra object id that Connect-style matching reads. Impact of the second is `[UNVERIFIED]` (needs the Entra lab, T-0075) | log t1 |
| R5 policy-hints control | **Confirmed.** A principal holding only Reset-Password (CA) on the OU can send `1.2.840.113556.1.4.2239` (value `30 03 02 01 01`): the control is accepted and history and minimum age are enforced (`53 unwillingToPerform`, DSID-031A12C5, Win32 0x52D). The same resets without the control succeed, including reuse of an old password. No extra right needed. Domain policy here: history 24, minimum age 1 day | log t2 |
| R9 / TM-Q27 restore by GUID | **Confirmed: no list right on `CN=Deleted Objects` is needed.** A principal with only Reanimate-Tombstones at the domain root, Create-Child `user` on the target OU and WP on `user` descendants restored a tombstone with one modify on `<GUID=…>` (Show-Deleted control, `delete isDeleted` + `replace distinguishedName`). Same principal: listing `CN=Deleted Objects` returns 0 entries and a base read of the GUID returns `32 noSuchObject`, so it cannot pre-check or read the object. Negative twins: no Reanimate right → `32 noSuchObject` (the DC hides the object); Reanimate but no Create-Child on the target container → `50 insufficientAccessRights` | log t3, t4 |
| R9 default container ACL | Not re-read here (`dsacls` on the container failed over WinRM); the KB 892806 statement stays a document claim. The behaviour above is consistent with it (the restorer saw nothing) | log s4 |
| gPLink GUID (§ classifier) | **Confirmed**: schemaIDGUID of `gPLink` is `f30e3bbe-9ff0-11d1-b603-0000f80367c1` on this schema. The classifier still reads it from the schema | log p1 |
| `pwdLastSet` = -1 (AD half of G17) | **Confirmed**: setting `-1` on an account at `0` (must change) stores the current time (`134377010751025896`), clears must-change, and the old password then binds. At `0` the bind fails (`invalidCredentials`). The Entra SSPR half of G17 is untested | log t5 |
| gMSA retrieval on Linux (§ connector identity) | **Retrieval confirmed, use as an identity not.** A member of `PrincipalsAllowedToRetrieveManagedPassword` read `msDS-ManagedPassword` over LDAPS from Linux (blob v1, 258-byte current password); a non-member got no value; plaintext 389 refused (`strongerAuthRequired`). The password is random UTF-16 and contains lone surrogates, so it cannot be turned into valid UTF-8 for a simple bind or a Kerberos string-to-key; a Linux client would need NT-hash/RC4 or a derivation we have not proven. Keep the AES keytab account for `linux-oci` | log t5, t6 |
| Inter-site replication interval | **Text was wrong, default not lab-derivable.** `replInterval` must be a multiple of 15, min 15, max 10 080 minutes ([Repl-Interval](https://learn.microsoft.com/en-us/windows/win32/adschema/a-replinterval)); a new link made by `New-ADReplicationSiteLink` has **no** `replInterval` attribute in this lab. The Microsoft page gives no default; 180 is `[UNVERIFIED]` common knowledge. The residual window is "the configured link interval, 15 minutes minimum" | log s5, s6 |

## Not checkable in the Windows lab (left tagged, with the reason)
- Entra-side items (G6–G8, G10–G15, G17 SSPR half, G18, TM-D25 PIM, Connect flows, E5, Graph permission rows,
  `addKey` licensing): need a tenant. Owner T-0075 (`lab/entra`).
- Samba runtime confirmation of the constructed attributes (§ Samba): a Samba-lab check, not a Windows one.
  Windows side already proven in `dc-read-paths-20261028.md`.
- krb5 acceptor replay detection and channel binding: needs the Linux adapter running; no adapter exists yet.
- `LdapEnforceChannelBinding` value: still open from T-0210.

## Lab changes left on dc1
A KDS root key (effective -10 h) was added for the gMSA test; `OU=T0076` and its objects, and the gMSA, were removed.
