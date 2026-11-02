//go:build windows

package agent

import (
	"sync"
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

const (
	steadyCPURate = 500   // percent * 100 of all cores: 5 % (spec resource limits)
	burstCPURate  = 10000 // 100 %: effectively uncapped; used only for connection set-up
)

var (
	confMu    sync.Mutex
	confJob   windows.Handle // 0 until Confine succeeded
	confBurst int            // Burst windows currently open
)

func setCPURate(job windows.Handle, rate uint32) error {
	cpu := jobCPURate{ControlFlags: cpuRateEnable | cpuRateHardCap, CPURate: rate}
	_, err := windows.SetInformationJobObject(job, jobObjectCPURateControlInformation, uintptr(unsafe.Pointer(&cpu)), uint32(unsafe.Sizeof(cpu)))
	return err
}

// Confine places the process in a job object with a hard CPU cap, a working-set ceiling and a
// below-normal priority, so a runaway collector cannot starve a domain controller (spec resource
// limits: <= 5 % of one core, 256 MiB). It is idempotent: the idle enrolment loop calls it on every
// pass and the process must be in exactly one job. Contract:
// https://learn.microsoft.com/en-us/windows/win32/api/jobapi2/nf-jobapi2-setinformationjobobject
func Confine() error {
	confMu.Lock()
	defer confMu.Unlock()
	if confJob != 0 {
		return nil
	}
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return err
	}
	// The job handle is deliberately kept open for the life of the process: closing it would not lift
	// the limits (KILL_ON_JOB_CLOSE is not set) but Burst needs it to restore the cap.
	if err := setCPURate(job, steadyCPURate); err != nil {
		_ = windows.CloseHandle(job)
		return err
	}
	var lim windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	lim.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_PROCESS_MEMORY | windows.JOB_OBJECT_LIMIT_PRIORITY_CLASS
	lim.ProcessMemoryLimit = 256 << 20
	lim.BasicLimitInformation.PriorityClass = windows.BELOW_NORMAL_PRIORITY_CLASS
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&lim)), uint32(unsafe.Sizeof(lim))); err != nil {
		_ = windows.CloseHandle(job)
		return err
	}
	if err := windows.AssignProcessToJobObject(job, windows.CurrentProcess()); err != nil {
		_ = windows.CloseHandle(job)
		return err
	}
	confJob = job
	return nil
}

// Burst lifts the CPU cap until the returned function is called (the memory ceiling and the priority
// stay). It exists for connection set-up only: measured on a domain controller (T-1249), dial, TLS
// handshake and stream open take about 1.3 s uncapped and 25-34 s under the 5 % hard cap, which made
// a freshly enrolled agent wait half a minute to connect. Windows are reference-counted, short and
// bounded by the caller; the cap is restored when the last one closes. Before Confine (or if lifting
// fails) it is a no-op, never an error: the agent then simply connects slowly.
func Burst() func() {
	confMu.Lock()
	defer confMu.Unlock()
	if confJob == 0 {
		return func() {}
	}
	if confBurst == 0 {
		if err := setCPURate(confJob, burstCPURate); err != nil {
			return func() {}
		}
	}
	confBurst++
	var once sync.Once
	return func() {
		once.Do(func() {
			confMu.Lock()
			defer confMu.Unlock()
			confBurst--
			if confBurst == 0 {
				_ = setCPURate(confJob, steadyCPURate) // if this fails the cap stays lifted until the next Burst window closes and retries
			}
		})
	}
}
