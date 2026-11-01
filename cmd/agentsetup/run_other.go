//go:build !windows

package main

import "fmt"

func run([]string) int {
	fmt.Println("agentsetup: Windows only")
	return 2
}
