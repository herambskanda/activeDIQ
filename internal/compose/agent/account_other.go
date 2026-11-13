//go:build !windows

package agent

import "github.com/skenzeriq/activediq/internal/platform/fleet/dial"

// Off Windows the state belongs to the user running enroll, who is the user running the component.
func enrolOptions() []dial.Option { return nil }
