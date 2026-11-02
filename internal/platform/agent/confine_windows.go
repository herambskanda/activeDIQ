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
	confMu  sync.Mutex
	confJob windows.Handle // 0 until Confine succeeded
	// capState drives Burst; its setter reads confJob without confMu because it only runs after Confine
	// set confJob and called arm() (capState.mu orders the two).
	capState = newCPUCap(steadyCPURate, burstCPURate, func(rate uint32) error { return setCPURate(confJob, rate) })
)

// cpuRateOf reads the CPU rate control back from a job (NULL = the calling process's job). Used by the
// tests to prove the cap is lifted and restored. Contract:
// https://learn.microsoft.com/en-us/windows/win32/api/jobapi2/nf-jobapi2-queryinformationjobobject
func cpuRateOf(job windows.Handle) (flags, rate uint32, err error) {
	var cpu jobCPURate
	var n uint32
	if err := windows.QueryInformationJobObject(job, jobObjectCPURateControlInformation, uintptr(unsafe.Pointer(&cpu)), uint32(unsafe.Sizeof(cpu)), &n); err != nil {
		return 0, 0, err
	}
	return cpu.ControlFlags, cpu.CPURate, nil
}

// SetCapReporter wires the report of a CPU cap that could not be restored (events 105/106).
func SetCapReporter(r CapReporter) { capState.setReporter(r) }

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
	capState.arm()
	return nil
}

// Burst lifts the CPU cap until the returned function is called (the memory ceiling and the priority
// stay). It exists for connection set-up only: measured on a domain controller (T-1249), dial, TLS
// handshake and stream open take about 1.3 s uncapped and 25-34 s under the 5 % hard cap, which made
// a freshly enrolled agent wait half a minute to connect. Windows are reference-counted, short and
// bounded by the caller. Putting the cap back is retried at once and then in the background until it
// succeeds, and a failure is reported to the event log (cpucap.go). Before Confine (or if lifting
// fails) it is a no-op, never an error: the agent then simply connects slowly, still capped.
func Burst() func() { return capState.begin() }
