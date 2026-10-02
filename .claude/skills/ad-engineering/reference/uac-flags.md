# userAccountControl flags

Source: https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties
and https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-user-account-control-computed.
Decode and encode only through the `attr.UAC` codec — never with ad-hoc bit math in feature code.

| Flag | Hex | Decimal | Settable via UAC? | Notes |
| --- | --- | --- | --- | --- |
| SCRIPT | `0x0001` | 1 | yes | Logon script runs. Legacy. |
| ACCOUNTDISABLE | `0x0002` | 2 | yes | Disabled. Bit-AND filter: `(userAccountControl:1.2.840.113556.1.4.803:=2)`. |
| HOMEDIR_REQUIRED | `0x0008` | 8 | yes | Legacy. |
| LOCKOUT | `0x0010` | 16 | **no** | **Unreliable here.** Use `msDS-User-Account-Control-Computed` bit `0x10`. Unlock with `lockoutTime=0`. |
| PASSWD_NOTREQD | `0x0020` | 32 | yes | Account may have an empty password. Security-report finding. |
| PASSWD_CANT_CHANGE | `0x0040` | 64 | **no** | Implemented as deny ACEs on the "Change Password" extended right, not this bit. Read and write the ACEs via the typed SD model. |
| ENCRYPTED_TEXT_PWD_ALLOWED | `0x0080` | 128 | yes | Reversible encryption. Security-report finding. |
| TEMP_DUPLICATE_ACCOUNT | `0x0100` | 256 | yes | Legacy. |
| NORMAL_ACCOUNT | `0x0200` | 512 | yes | A normal user. Enabled user = 512, disabled = 514. |
| INTERDOMAIN_TRUST_ACCOUNT | `0x0800` | 2048 | — | Trust account. |
| WORKSTATION_TRUST_ACCOUNT | `0x1000` | 4096 | yes | Computer (member). 4096 enabled. |
| SERVER_TRUST_ACCOUNT | `0x2000` | 8192 | — | Domain controller. 532480 = DC + TRUSTED_FOR_DELEGATION. |
| DONT_EXPIRE_PASSWORD | `0x10000` | 65536 | yes | Security-report finding on user accounts. |
| MNS_LOGON_ACCOUNT | `0x20000` | 131072 | yes | Majority node set. Legacy. |
| SMARTCARD_REQUIRED | `0x40000` | 262144 | yes | Setting it scrambles the password hash. |
| TRUSTED_FOR_DELEGATION | `0x80000` | 524288 | yes (privileged) | Unconstrained delegation. High-risk finding on non-DCs. |
| NOT_DELEGATED | `0x100000` | 1048576 | yes | "Sensitive and cannot be delegated". Recommended for admins. |
| USE_DES_KEY_ONLY | `0x200000` | 2097152 | yes | Weak crypto finding. |
| DONT_REQ_PREAUTH | `0x400000` | 4194304 | yes | AS-REP roastable. High-risk finding. |
| PASSWORD_EXPIRED | `0x800000` | 8388608 | **no** | **Unreliable here.** Use computed bit `0x800000`, or `msDS-UserPasswordExpiryTimeComputed`. |
| TRUSTED_TO_AUTH_FOR_DELEGATION | `0x1000000` | 16777216 | yes (privileged) | Protocol transition (constrained delegation with any auth). Finding. |
| PARTIAL_SECRETS_ACCOUNT | `0x04000000` | 67108864 | — | Read-only domain controller. |

## Rules

- **Read-modify-write the whole integer** under compare-and-swap (delete old value + add new value
  in one modify) — never `replace` with a value computed from a stale read, or you silently undo
  a concurrent change to another bit.
- Writing UAC requires the right flags together: enabling a user = clear `ACCOUNTDISABLE`, keep
  `NORMAL_ACCOUNT`. A user with no password set cannot be enabled unless `PASSWD_NOTREQD` is set —
  set the password first; never set `PASSWD_NOTREQD` as a workaround.
- Setting `TRUSTED_FOR_DELEGATION` needs `SeEnableDelegationPrivilege` — a privileged operation:
  `security-sensitive` ticket and an audit event.
- Security reports built on these bits name the source attribute and whether the value came from
  the stored or computed attribute.
