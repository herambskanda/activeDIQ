# Building the agent MSI

```
wix build Agent.wxs -ext WixToolset.Util.wixext -arch x64 -wx -sw1149 \
  -d Version=<x.y.z> -d AgentExe=<path>\activediq-agent.exe -d SetupExe=<path>\agentsetup.exe -o activediq-agent-<x.y.z>.msi
```

WiX Toolset 5.0.2 (see the licence register). `-wx` turns every warning into an error, so the build fails on any warning that has not been
suppressed on purpose. There is exactly one suppression, **`-sw1149`**:

* WIX1149 ("ServiceConfig functionality is documented in the Windows Installer SDK to not work as expected") is raised by the **core**
  `ServiceConfig` element itself. That element is the only one that can set `ServiceSid="restricted"` and `RequiredPrivilege`
  (`util:ServiceConfig` has neither), and ADR-0006 A2 needs both. The lab run T-0648 read back on a Windows Server DC that it applies
  the restricted SID type and the single privilege (`sc qprivs`, the running token).
* The recovery actions (`restart` x3, 30 s, reset 1 day) are on `util:ServiceConfig`, which is the only element that has them: the
  core `ServiceConfig` has no failure-action attributes (WIX0004 with WiX 5.0.2). `sc qfailure activeDIQAgent` reads them back (T-0833).

The CI/release pipeline owned by devops-engineer must use the same flags. `lab/windows/bin/agent-unenrolled-verify` checks both
fixtures (without `-sw1149` the build fails on WIX1149; a failure attribute on the core element fails with WIX0004).
