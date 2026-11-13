//go:build windows && windowslab

package agent

import (
	"context"
	"encoding/binary"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"google.golang.org/grpc"

	kernel "github.com/skenzeriq/activediq/internal/platform/agent"
	"github.com/skenzeriq/activediq/internal/platform/agentpolicy"
	"github.com/skenzeriq/activediq/internal/platform/fleet"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
	addcv1 "github.com/skenzeriq/activediq/internal/proto/activediq/addc/v1"
	agentv1 "github.com/skenzeriq/activediq/internal/proto/skenzeriq/agent/v1"
)

// Lab measurements for the ADR-0006 / contract section 5 resource bounds (T-0557). They need a Windows
// lab DC and an elevated token, and each test confines the whole test process exactly as the agent
// service does (kernel.Confine), so run each with its own -test.run in its own process:
//
//	GOOS=windows go test -c -tags windowslab -o resource.test.exe ./internal/compose/agent
//
// lab/windows/guest/agent-t0557.ps1 runs them. Every number is printed as a "LAB name key=value ..." line.

var (
	labSeconds = flag.Int("labsecs", 0, "TestLabResourceLoad: seconds to collect under the confined job")
	labRate    = flag.Uint("labrate", 3000, "TestLabResourceLoad: the policy / local ceiling events per second")
	labAfter   = flag.Uint64("labafter", 0, "TestLabResourceCatchUp: start collecting after this Security record id (the bookmark)")
	labData    = flag.String("labdata", `C:\ProgramData\skenzeriq\agent\t0557-lab`, "TestLabResourceLoad: data directory (inside the MSI's pinned DACL)")
)

func labLine(name string, kv ...any) {
	s := "LAB " + name
	for i := 0; i+1 < len(kv); i += 2 {
		s += fmt.Sprintf(" %v=%v", kv[i], kv[i+1])
	}
	fmt.Println(s)
}

func ftDur(f windows.Filetime) time.Duration {
	return time.Duration(uint64(f.HighDateTime)<<32|uint64(f.LowDateTime)) * 100
}

func cpuUsed() time.Duration {
	var c, e, k, u windows.Filetime
	if err := windows.GetProcessTimes(windows.CurrentProcess(), &c, &e, &k, &u); err != nil {
		return 0
	}
	return ftDur(k) + ftDur(u)
}

// processMemoryCountersEx is PROCESS_MEMORY_COUNTERS_EX:
// https://learn.microsoft.com/en-us/windows/win32/api/psapi/ns-psapi-process_memory_counters_ex
type processMemoryCountersEx struct {
	CB                         uint32
	PageFaultCount             uint32
	PeakWorkingSetSize         uintptr
	WorkingSetSize             uintptr
	QuotaPeakPagedPoolUsage    uintptr
	QuotaPagedPoolUsage        uintptr
	QuotaPeakNonPagedPoolUsage uintptr
	QuotaNonPagedPoolUsage     uintptr
	PagefileUsage              uintptr
	PeakPagefileUsage          uintptr
	PrivateUsage               uintptr
}

var procGetProcessMemoryInfo = windows.NewLazySystemDLL("psapi.dll").NewProc("GetProcessMemoryInfo")

func memory(t *testing.T) processMemoryCountersEx {
	var m processMemoryCountersEx
	m.CB = uint32(unsafe.Sizeof(m))
	r, _, e := procGetProcessMemoryInfo.Call(uintptr(windows.CurrentProcess()), uintptr(unsafe.Pointer(&m)), uintptr(m.CB))
	if r == 0 {
		t.Fatalf("GetProcessMemoryInfo: %v", e)
	}
	return m
}

func mib(n uintptr) string { return fmt.Sprintf("%.1f", float64(n)/(1<<20)) }

func confined(t *testing.T) {
	t.Helper()
	if err := kernel.Confine(); err != nil {
		t.Fatalf("Confine: %v", err)
	}
}

// What the job really enforces: the priority class read back from the process, the job's memory limit
// read back from QueryInformationJobObject, and a VirtualAlloc commit past it that must fail.
func TestLabJobLimitsReadBack(t *testing.T) {
	confined(t)
	labLine("priority", "class", fmt.Sprintf("%#x", mustPriority(t)), "below_normal", mustPriority(t) == windows.BELOW_NORMAL_PRIORITY_CLASS)

	var lim windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	var n uint32
	if err := windows.QueryInformationJobObject(0, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&lim)), uint32(unsafe.Sizeof(lim)), &n); err != nil {
		t.Fatalf("QueryInformationJobObject: %v", err)
	}
	f := lim.BasicLimitInformation.LimitFlags
	labLine("job", "limit_flags", fmt.Sprintf("%#x", f),
		"process_memory_limit", f&windows.JOB_OBJECT_LIMIT_PROCESS_MEMORY != 0,
		"process_memory_limit_mib", mib(lim.ProcessMemoryLimit),
		"workingset_limit", f&windows.JOB_OBJECT_LIMIT_WORKINGSET != 0)

	// A commit past the ceiling fails; one under it succeeds. (It is a committed-memory limit, not a
	// working-set limit: JOB_OBJECT_LIMIT_PROCESS_MEMORY.)
	under, uerr := windows.VirtualAlloc(0, 128<<20, windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if uerr == nil {
		_ = windows.VirtualFree(under, 0, windows.MEM_RELEASE)
	}
	over, oerr := windows.VirtualAlloc(0, 300<<20, windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if oerr == nil {
		_ = windows.VirtualFree(over, 0, windows.MEM_RELEASE)
	}
	labLine("commit_probe", "commit_128mib_ok", uerr == nil, "commit_300mib_ok", oerr == nil, "commit_300mib_err", oerr)
	if oerr == nil {
		t.Errorf("a 300 MiB commit succeeded inside the 256 MiB job")
	}
	if uerr != nil {
		t.Errorf("a 128 MiB commit failed: %v", uerr)
	}
}

func mustPriority(t *testing.T) uint32 {
	p, err := windows.GetPriorityClass(windows.CurrentProcess())
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// A pure CPU burn inside the job measures what the 5 % hard cap really lets through, as a share of all
// logical processors and of one core.
func TestLabCPUCapMeasured(t *testing.T) {
	confined(t)
	secs := 12
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(secs)*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	for i := 0; i < runtime.NumCPU(); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			x := 1.0
			for ctx.Err() == nil {
				for j := 0; j < 100000; j++ {
					x = x*1.0000001 + 0.5
				}
			}
			_ = x
		}()
	}
	c0, w0 := cpuUsed(), time.Now()
	wg.Wait()
	cpu, wall := cpuUsed()-c0, time.Since(w0)
	ncpu := runtime.NumCPU()
	allPct := 100 * cpu.Seconds() / wall.Seconds() / float64(ncpu)
	onePct := 100 * cpu.Seconds() / wall.Seconds()
	labLine("cpu_cap", "logical_cpus", ncpu, "wall_s", fmt.Sprintf("%.1f", wall.Seconds()), "cpu_s", fmt.Sprintf("%.2f", cpu.Seconds()),
		"pct_of_all_cpus", fmt.Sprintf("%.2f", allPct), "pct_of_one_core", fmt.Sprintf("%.1f", onePct))
}

type drain struct {
	got, batches atomic.Uint64
}

func (d *drain) SubmitEvents(_ context.Context, in *agentv1.SubmitEventsRequest, _ ...grpc.CallOption) (*agentv1.SubmitEventsResponse, error) {
	d.got.Add(uint64(len(in.Events)))
	d.batches.Add(1)
	if len(in.Events) == 0 {
		return &agentv1.SubmitEventsResponse{}, nil
	}
	return &agentv1.SubmitEventsResponse{Accepted: uint64(len(in.Events)), HighestStoredSeq: in.Events[len(in.Events)-1].AgentSeq}, nil
}

// TestLabResourceLoad runs the real host, the real addc collector, the real wevtapi source and the real
// outbox on disk inside the real job, on the Security channel while another process generates events
// (the guest script). The sender hands batches to an in-process client that accepts them (there is no
// ingest server in the lab, and no network is part of this measurement).
func TestLabResourceLoad(t *testing.T) {
	if *labSeconds == 0 {
		t.Skip("run by agent-t0557.ps1 with -labsecs")
	}
	confined(t)
	_ = os.RemoveAll(*labData)
	tid, _ := tenant.Parse("11111111-1111-4111-8111-111111111111")
	id := fleet.Identity{Tenant: tid, Kind: fleet.KindADDC, ComponentID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}
	mod, _ := buildModule(fleet.KindADDC, "lab")
	ceil := kernel.Ceilings{OutboxMaxBytes: 64 << 20, BatchMaxBytes: 256 << 10, MaxEventsPerSecond: uint32(*labRate)}
	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelWarn}))
	h, err := kernel.Open(kernel.Config{Identity: id, DataDir: filepath.Clean(*labData), Version: "t0557", Module: mod, Ceilings: ceil, Logger: log})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	// The ids the agent really asks for: the whole Security catalogue the audit reports use.
	pol := agentpolicy.AddcPolicy{Password: agentpolicy.PasswordRules{MinLength: 8, MaxLength: 64}}
	pol.Events = agentpolicy.EventRules{CollectionEnabled: true, Channels: []agentpolicy.Channel{agentpolicy.ChannelSecurity},
		EventIDs: []uint32{4624, 4634, 4647, 4648, 4768, 4769, 4776}, MaxEventsPerSecond: uint32(*labRate),
		BatchMaxBytes: ceil.BatchMaxBytes, OutboxMaxBytes: ceil.OutboxMaxBytes}
	if err := mod.Activate(pol); err != nil {
		t.Fatal(err)
	}
	d := &drain{}
	h.SetEventClient(d)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- h.Run(ctx) }()

	time.Sleep(3 * time.Second) // subscription up before the generator is released
	fmt.Println("LAB ready")    // the guest script waits for this line before it starts the generator
	c0, w0 := cpuUsed(), time.Now()
	var peakWS, peakPriv uintptr
	var samples []float64
	last, lastT := c0, w0
	end := w0.Add(time.Duration(*labSeconds) * time.Second)
	for time.Now().Before(end) {
		time.Sleep(time.Second)
		m := memory(t)
		peakWS, peakPriv = max(peakWS, m.PeakWorkingSetSize), max(peakPriv, m.PrivateUsage)
		now, c := time.Now(), cpuUsed()
		samples = append(samples, 100*(c-last).Seconds()/now.Sub(lastT).Seconds()/float64(runtime.NumCPU()))
		last, lastT = c, now
	}
	cpu, wall := cpuUsed()-c0, time.Since(w0)
	st := h.Outbox().Stats()
	var collected, throttled, gaps uint64
	if cs, ok := mod.(interface {
		GetCollectionState(context.Context, *addcv1.GetCollectionStateRequest) (*addcv1.GetCollectionStateResponse, error)
	}); ok {
		r, _ := cs.GetCollectionState(context.Background(), &addcv1.GetCollectionStateRequest{})
		for _, c := range r.GetChannels() {
			collected, throttled, gaps = collected+c.EventsCollected, throttled+c.EventsThrottled, gaps+c.GapsSeen
		}
	}
	cancel()
	<-done
	worst := 0.0
	for _, s := range samples {
		worst = max(worst, s)
	}
	labLine("load", "logical_cpus", runtime.NumCPU(), "wall_s", fmt.Sprintf("%.1f", wall.Seconds()), "cpu_s", fmt.Sprintf("%.2f", cpu.Seconds()),
		"avg_pct_of_all_cpus", fmt.Sprintf("%.2f", 100*cpu.Seconds()/wall.Seconds()/float64(runtime.NumCPU())),
		"worst_1s_pct", fmt.Sprintf("%.2f", worst), "peak_working_set_mib", mib(peakWS), "peak_private_mib", mib(peakPriv),
		"outbox_records", st.Records, "outbox_dropped", st.Dropped, "outbox_write_errors", st.WriteErrors, "last_seq", st.LastSeq,
		"delivered_to_drain", d.got.Load(), "events_per_s_delivered", fmt.Sprintf("%.0f", float64(d.got.Load())/wall.Seconds()),
		"policy_rate_cap", *labRate, "collected", collected, "throttled", throttled, "gaps", gaps)
}

// TestLabResourceCatchUp is the capacity half of the measurement. A logon generator on a four-processor lab DC
// cannot produce 3 000 catalogued events a second, so this reads the Security log's existing backlog from
// -labafter through the same confined host, collector, wevtapi source and on-disk outbox, with the policy rate
// raised so the throttle does not hide the cost. The events/s it sustains under the 5 % hard cap is the figure
// that bounds a real flood (and a catch-up after the agent was stopped, which resubscribes from the bookmark).
func TestLabResourceCatchUp(t *testing.T) {
	if *labAfter == 0 {
		t.Skip("run by agent-t0557.ps1 with -labafter")
	}
	confined(t)
	_ = os.RemoveAll(*labData)
	b, err := kernel.NewBlobs(filepath.Join(*labData, "module"))
	if err != nil {
		t.Fatal(err)
	}
	var bm [8]byte
	binary.BigEndian.PutUint64(bm[:], *labAfter)
	if err := b.Save("bookmark-security", bm[:]); err != nil {
		t.Fatal(err)
	}
	tid, _ := tenant.Parse("11111111-1111-4111-8111-111111111111")
	id := fleet.Identity{Tenant: tid, Kind: fleet.KindADDC, ComponentID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}
	mod, _ := buildModule(fleet.KindADDC, "lab")
	ceil := kernel.Ceilings{OutboxMaxBytes: 256 << 20, BatchMaxBytes: 256 << 10, MaxEventsPerSecond: 100000}
	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelWarn}))
	h, err := kernel.Open(kernel.Config{Identity: id, DataDir: filepath.Clean(*labData), Version: "t0557", Module: mod, Ceilings: ceil, Logger: log})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	pol := agentpolicy.AddcPolicy{Password: agentpolicy.PasswordRules{MinLength: 8, MaxLength: 64}}
	pol.Events = agentpolicy.EventRules{CollectionEnabled: true, Channels: []agentpolicy.Channel{agentpolicy.ChannelSecurity},
		EventIDs: []uint32{4624, 4634, 4647, 4648, 4768, 4769, 4776}, MaxEventsPerSecond: 100000,
		BatchMaxBytes: ceil.BatchMaxBytes, OutboxMaxBytes: ceil.OutboxMaxBytes}
	if err := mod.Activate(pol); err != nil {
		t.Fatal(err)
	}
	d := &drain{}
	h.SetEventClient(d)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- h.Run(ctx) }()
	c0, w0 := cpuUsed(), time.Now()
	state := func() (coll, thr, gaps, last uint64) {
		cs := mod.(interface {
			GetCollectionState(context.Context, *addcv1.GetCollectionStateRequest) (*addcv1.GetCollectionStateResponse, error)
		})
		r, _ := cs.GetCollectionState(context.Background(), &addcv1.GetCollectionStateRequest{})
		for _, c := range r.GetChannels() {
			coll, thr, gaps = coll+c.EventsCollected, thr+c.EventsThrottled, gaps+c.GapsSeen
			last = max(last, c.LastEventRecordId)
		}
		return
	}
	// Done when the collected count stops moving for 5 s (the backlog is drained and the tail is quiet).
	var prev, still uint64
	var peakWS, peakPriv uintptr
	deadline := w0.Add(10 * time.Minute)
	for time.Now().Before(deadline) {
		time.Sleep(time.Second)
		m := memory(t)
		peakWS, peakPriv = max(peakWS, m.PeakWorkingSetSize), max(peakPriv, m.PrivateUsage)
		coll, _, _, _ := state()
		if coll == prev && coll > 0 {
			still++
		} else {
			still = 0
		}
		prev = coll
		if still >= 5 {
			break
		}
	}
	cpu, wall := cpuUsed()-c0, time.Since(w0)-5*time.Second
	coll, thr, gaps, last := state()
	cancel()
	<-done
	st := h.Outbox().Stats()
	labLine("catchup", "logical_cpus", runtime.NumCPU(), "after_record", *labAfter, "last_record", last, "collected", coll, "throttled", thr, "gaps", gaps,
		"wall_s", fmt.Sprintf("%.1f", wall.Seconds()), "cpu_s", fmt.Sprintf("%.2f", cpu.Seconds()),
		"events_per_s", fmt.Sprintf("%.0f", float64(coll)/wall.Seconds()),
		"pct_of_all_cpus", fmt.Sprintf("%.2f", 100*cpu.Seconds()/wall.Seconds()/float64(runtime.NumCPU())),
		"cpu_us_per_event", fmt.Sprintf("%.0f", cpu.Seconds()*1e6/float64(max(coll, 1))),
		"peak_working_set_mib", mib(peakWS), "peak_private_mib", mib(peakPriv),
		"outbox_records", st.Records, "outbox_dropped", st.Dropped, "delivered_to_drain", d.got.Load())
}
