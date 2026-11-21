# T-1464 QA (build 704a57f88) - run by qa-verifier, own fixtures in /tmp/qa1464 (throw-away trees, -root)
AC1: 6 libs (go-ldap, jcmturner gokrb5, go-krb5, msgraph-sdk-go, MSAL, azidentity) x {internal/modules/users -> rc=1 FF-SP1 [ldap|kerberos|graph-library]; internal/connector/ad -> rc=0}.
     credential fixtures (own credential pkg with Source/Secret/Bind + Unseal): field, param, composite literal outside connector -> rc=1 directory-credential-type;
     k.Unseal() in modules/users and compose/server -> rc=1 directory-credential-unseal; same in internal/connector/ad -> rc=0; compose/server taking+returning credential.Source by value -> rc=0.
AC2: policy.LDAPLibraries/KerberosLibraries/GraphLibraries (tools/analyzers/policy/policy.go:186-193) are the only definitions used by rules.go; scan_test.go:997-1001 asserts equality with the rule prefixes.
AC3: `go run ./tools/fitness/safeprim -p3` -> "P3 static ok (7 rules)", rc=0 on the branch; `go run ./tools/fitness/profiles` -> "P3 ACTIVE, DEFERRED (T-0929 ...), static half passing". Negative: go-ldap import added in a git copy -> profiles row "STATIC HALF FAILING", violation reported, rc=1 even though the deferral covers Command.
Profiles: only P7 violations (4 local-only branches, environment, not CI) remain; go test ./tools/fitness/profiles ok.
