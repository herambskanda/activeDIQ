package main

import "testing"

// T-0776: the WiX preprocessor must not read environment variables (CI secrets) into the MSI.
func TestT0776WixEnvReference(t *testing.T) {
	mk := func(allow []string, path, body string) Result {
		r := t.TempDir()
		write(t, r, "packaging/windows/agent.wxs", goodWxs)
		if path != "" {
			write(t, r, path, body)
		}
		return checkInstallerAllow(r, allow)
	}
	wantClean(t, mk(nil, "", ""))
	bad := map[string]string{
		"attribute":    `<Include xmlns="http://wixtoolset.org/schemas/v4/wxs"><Property Id="X" Value="$(env.CI_SIGNING_PASSWORD)"/></Include>`,
		"text":         `<Include xmlns="http://wixtoolset.org/schemas/v4/wxs"><Property Id="X">$(env.CI_SIGNING_PASSWORD)</Property></Include>`,
		"define":       `<Include xmlns="http://wixtoolset.org/schemas/v4/wxs"><?define S = $(env.CI_SIGNING_PASSWORD) ?><Property Id="X" Value="$(var.S)"/></Include>`,
		"define quote": `<Include xmlns="http://wixtoolset.org/schemas/v4/wxs"><?define S = "$(env.X)" ?></Include>`,
		"bang":         `<Include xmlns="http://wixtoolset.org/schemas/v4/wxs"><Property Id="X" Value="!(env.X)"/></Include>`,
		"mixed case":   `<Include xmlns="http://wixtoolset.org/schemas/v4/wxs"><Property Id="X" Value="$(Env.X)"/></Include>`,
		"spaced":       `<Include xmlns="http://wixtoolset.org/schemas/v4/wxs"><Property Id="X" Value="$( ENV . X)"/></Include>`,
	}
	for _, body := range bad {
		for _, f := range []string{"packaging/windows/extra.wxi", "packaging/windows/extra.wxs"} {
			wantViolation(t, mk(nil, f, body), "T-0776")
			wantViolation(t, mk([]string{f, "WriteConfig"}, f, body), "T-0776")
		}
	}
}
