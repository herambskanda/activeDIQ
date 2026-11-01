//go:build !lab

package main

// labAccountCommand is the production half of account_lab.go: no lab subcommand exists, so every name falls
// through to the generic `account` handling. It is a plain function, not a hook set from an init, so main's
// first statement stays prochardening.Apply (TM-TB16-T6).
func labAccountCommand(string, []string) (code int, ok bool) { return 0, false }
