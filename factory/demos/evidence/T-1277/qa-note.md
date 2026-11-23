# T-1277 QA evidence (build 2681a4097)
AC1 — Linux half PASS: go test -race -count=1 on platform/agent, compose/agent, fleet/tunnelclient all pass
(go-test-linux.txt). TestUnreachableServerWritesOneClassedEvent: real tunnelclient vs closed port, 4 s, exactly one event 110, no addr/port/key text.
TestEventsCarryNoAttributeData, TestTunnelFailureClassIsReportedOncePerInterval, TestEveryTunnelClassHasADocumentedID pass.
GOOS=windows go vet + go build ./cmd/agent OK. Runbook dc-agent-operations.md documents 110-119 matching svclog.go constants.
AC1 — Windows half BLOCKED: no Windows lab here (no virsh, dc1 192.168.77.10 unreachable, no .win-lab.env).
The actual ReportEventW write / Application-log entry, and the Windows EventLog close test, were not run.
Not a UI ticket: no screens/controls.
