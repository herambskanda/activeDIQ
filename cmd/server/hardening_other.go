//go:build !linux

package main

// disableDumps is a no-op off Linux: the self-hosted server target is linux-oci; Windows dump
// policy is set by the service installer (WER LocalDumps), not by the process.
func disableDumps() error { return nil }
