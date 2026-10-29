//go:build windows

package agent

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// x/sys/windows has no JOBOBJECT_CPU_RATE_CONTROL_INFORMATION; layout and values from
// https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_cpu_rate_control_information
type jobCPURate struct{ ControlFlags, CPURate uint32 }

const (
	cpuRateEnable                      = 0x1
	cpuRateHardCap                     = 0x4
	jobObjectCPURateControlInformation = 15
)

// Confine places the process in a job object with a hard CPU cap, a working-set ceiling and a
// below-normal priority, so a runaway collector cannot starve a domain controller (spec resource
// limits: <= 5 % of one core, 256 MiB). Contract:
// https://learn.microsoft.com/en-us/windows/win32/api/jobapi2/nf-jobapi2-setinformationjobobject
func Confine() error {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return err
	}
	// The job handle is deliberately kept open for the life of the process: closing it would not lift
	// the limits (KILL_ON_JOB_CLOSE is not set) but there is no reason to release it.
	cpu := jobCPURate{ControlFlags: cpuRateEnable | cpuRateHardCap, CPURate: 500} // percent * 100 of all cores: 5 %
	if _, err := windows.SetInformationJobObject(job, jobObjectCPURateControlInformation, uintptr(unsafe.Pointer(&cpu)), uint32(unsafe.Sizeof(cpu))); err != nil {
		return err
	}
	var lim windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	lim.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_PROCESS_MEMORY | windows.JOB_OBJECT_LIMIT_PRIORITY_CLASS
	lim.ProcessMemoryLimit = 256 << 20
	lim.BasicLimitInformation.PriorityClass = windows.BELOW_NORMAL_PRIORITY_CLASS
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&lim)), uint32(unsafe.Sizeof(lim))); err != nil {
		return err
	}
	return windows.AssignProcessToJobObject(job, windows.CurrentProcess())
}
