package operation

import (
	"context"
	"encoding/json/v2"
	"fmt"
	"math/rand/v2"
	"runtime"
	"slices"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/jobs"
	"github.com/skenzeriq/activediq/internal/platform/operation/step"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
)

// chunkedDir adds ChunkPlanner to the Postgres fixture's directory Action by planning a slice of the
// input's items through the Action's own Plan.
type chunkedDir struct{ Action }

// The optional interfaces the runner looks for are forwarded to the wrapped Action.
func (c chunkedDir) Observe(ctx context.Context, pins authority.Pins, p StepPlan, at time.Time) (Observation, error) {
	return c.Action.(Observer).Observe(ctx, pins, p, at)
}

func (c chunkedDir) PlanItems(in Input) (int, error) {
	var d dirIn
	if err := json.Unmarshal(in, &d); err != nil {
		return 0, err
	}
	return len(d.Items), nil
}

func (c chunkedDir) PlanChunk(ctx context.Context, pc PlanContext, in Input, first, n int) ([]StepPlan, error) {
	var d dirIn
	if err := json.Unmarshal(in, &d); err != nil {
		return nil, err
	}
	d.Items = d.Items[first:min(first+n, len(d.Items))]
	b, _ := json.Marshal(d)
	return c.Plan(ctx, pc, Input(b))
}

func (p *prig) bulkReq(n int) Request {
	items := make([]itemIn, n)
	for i := range items {
		items[i] = itemIn{GUID: fmt.Sprintf("g%05d", i), Want: "x"}
	}
	return p.req(items...)
}

// planJobs claims every available operation.plan job and returns its args.
func (p *prig) planJobs() []planArgs {
	p.t.Helper()
	var out []planArgs
	for {
		claimed := p.takeJobs(JobPlan)
		if len(claimed) == 0 {
			return out
		}
		out = append(out, p.completePlanJobs(claimed)...)
	}
}

func (p *prig) completePlanJobs(claimed []jobs.Claimed) []planArgs {
	var out []planArgs
	for _, c := range claimed {
		var a planArgs
		if err := decodeArgs(c.Args, &a); err != nil {
			p.t.Fatal(err)
		}
		out = append(out, a)
		if err := p.db.WithTenant(context.Background(), p.tn, func(ctx context.Context, tx store.Tx) error { return jobs.Complete(ctx, tx, c.Ref) }); err != nil {
			p.t.Fatal(err)
		}
	}
	return out
}

func (p *prig) planChunk(id step.OperationID, a planArgs) {
	p.t.Helper()
	a.Operation = string(id)
	if err := p.r.PlanChunk(context.Background(), p.tn, p.r.txFor(p.tn), a); err != nil {
		p.t.Fatal(err)
	}
}

func (p *prig) count(sql string, args ...any) int {
	p.t.Helper()
	var n int
	fmt.Sscan(p.owner(sql, args...)[0], &n)
	return n
}

// AC1 + AC3: a 20k-item plan is N chunk jobs of the configured size, each committing its own rows.
func TestChunkedPlan20kItems(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		p := newPRig(t, s, rigOpt{chunked: true})
		sub, err := p.r.SubmitDirectory(context.Background(), p.bulkReq(20000))
		if err != nil {
			t.Fatal(err)
		}
		if sub.State != OpPlanning || sub.Items != 20000 {
			t.Fatalf("sub = %+v", sub)
		}
		if n := p.count(`SELECT count(*) FROM public.operation_items`); n != 0 {
			t.Fatalf("items before any chunk ran = %d", n)
		}
		jobsOut := p.planJobs()
		if len(jobsOut) != 200 {
			t.Fatalf("plan jobs = %d, want 200 (20000 / chunk size 100)", len(jobsOut))
		}
		rand.Shuffle(len(jobsOut), func(i, j int) { jobsOut[i], jobsOut[j] = jobsOut[j], jobsOut[i] }) // order does not matter
		for i, a := range jobsOut {
			p.planChunk(sub.Operation, a)
			// Each chunk is committed on its own: after k chunks exactly k*100 items exist and the plan is not final.
			if i == 49 {
				if n := p.count(`SELECT count(*) FROM public.operation_items`); n != 5000 {
					t.Fatalf("items after 50 chunks = %d", n)
				}
				if st := p.opState(sub.Operation); st != "planning" {
					t.Fatalf("state after 50 chunks = %s", st)
				}
			}
		}
		if n := p.count(`SELECT count(*) FROM public.operation_plan_chunks WHERE items = 100`); n != 200 {
			t.Fatalf("recorded chunks = %d", n)
		}
		if n := p.count(`SELECT count(*) FROM public.operation_steps WHERE state = 'planned'`); n != 20000 {
			t.Fatalf("planned steps = %d", n)
		}
		if st := p.opState(sub.Operation); st == "planning" {
			t.Fatal("plan not finalised after the last chunk")
		}
		if h := p.owner(`SELECT COALESCE(plan_hash, '') FROM public.operations`)[0]; len(h) != 64 {
			t.Fatalf("plan hash = %q", h)
		}
		if n := p.count(`SELECT count(*) FROM public.operation_items WHERE item_no >= 0 AND item_no < 20000`); n != 20000 {
			t.Fatalf("item numbers = %d", n)
		}
	})
}

// The plan hash does not depend on the order chunks ran in, and a plan is the same whether chunks ran once or twice.
func TestChunkedPlanHashStable(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		hash := func(order func([]planArgs)) string {
			p := newPRig(t, s, rigOpt{chunked: true})
			sub, err := p.r.SubmitDirectory(context.Background(), p.bulkReq(350))
			if err != nil {
				t.Fatal(err)
			}
			js := p.planJobs()
			if len(js) != 4 {
				t.Fatalf("jobs = %d", len(js))
			}
			order(js)
			for _, a := range js {
				p.planChunk(sub.Operation, a)
				p.planChunk(sub.Operation, a) // a re-driven chunk is a no-op
			}
			return p.owner(`SELECT plan_hash FROM public.operations`)[0]
		}
		a := hash(func([]planArgs) {})
		b := hash(func(js []planArgs) { slices.Reverse(js) })
		if a != b {
			t.Fatalf("plan hash depends on chunk order: %s vs %s", a, b)
		}
	})
}

// AC2: a chunk that crashed is re-driven by the sweeper; chunks already recorded are not planned again.
func TestChunkedPlanSweeperRedrivesLostChunk(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		p := newPRig(t, s, rigOpt{chunked: true})
		p.r.cfg.StallWindow = time.Minute
		sub, err := p.r.SubmitDirectory(context.Background(), p.bulkReq(450))
		if err != nil {
			t.Fatal(err)
		}
		js := p.planJobs()
		if len(js) != 5 {
			t.Fatalf("jobs = %d", len(js))
		}
		for _, a := range js {
			if a.Chunk != 2 { // chunk 2's job is lost
				p.planChunk(sub.Operation, a)
			}
		}
		if st := p.opState(sub.Operation); st != "planning" {
			t.Fatalf("state = %s", st)
		}
		p.exec(`UPDATE public.operations SET updated_at = now() - interval '1 hour'`)
		if err := p.r.Sweep(context.Background(), p.tn, p.r.txFor(p.tn)); err != nil {
			t.Fatal(err)
		}
		re := p.planJobs()
		if len(re) != 1 || re[0].Chunk != 2 {
			t.Fatalf("sweeper re-drove %+v, want only chunk 2", re)
		}
		before := p.count(`SELECT count(*) FROM public.operation_items`)
		p.planChunk(sub.Operation, js[0]) // an already recorded chunk, replayed
		if p.count(`SELECT count(*) FROM public.operation_items`) != before {
			t.Fatal("a recorded chunk was planned again")
		}
		p.planChunk(sub.Operation, re[0])
		if st := p.opState(sub.Operation); st == "planning" {
			t.Fatal("not finalised")
		}
		if n := p.count(`SELECT count(*) FROM public.operation_items`); n != 450 {
			t.Fatalf("items = %d", n)
		}
	})
}

// A chunk planned for a superseded revision lands nothing.
func TestChunkedPlanStaleRevisionLandsNothing(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		p := newPRig(t, s, rigOpt{chunked: true})
		sub, err := p.r.SubmitDirectory(context.Background(), p.bulkReq(250))
		if err != nil {
			t.Fatal(err)
		}
		js := p.planJobs()
		p.exec(`UPDATE public.operations SET plan_revision = plan_revision + 1`)
		for _, a := range js {
			p.planChunk(sub.Operation, a)
		}
		if n := p.count(`SELECT count(*) FROM public.operation_items`) + p.count(`SELECT count(*) FROM public.operation_plan_chunks`); n != 0 {
			t.Fatalf("a superseded chunk landed %d rows", n)
		}
	})
}

// Fewer items than one chunk plan inline, exactly as before.
func TestSmallPlanStaysInline(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		p := newPRig(t, s, rigOpt{chunked: true})
		sub, err := p.r.SubmitDirectory(context.Background(), p.bulkReq(100))
		if err != nil {
			t.Fatal(err)
		}
		if sub.State == OpPlanning || len(p.takeJobs(JobPlan)) != 0 {
			t.Fatalf("a one-chunk plan went through plan jobs: %+v", sub)
		}
	})
}

// AC3: planning, finalising and routing a bulk operation is bounded by the chunk size, not the row count.
// It plans 5,000 rows (BULK2's CSV bound) and 20,000, samples the live heap after every chunk (and after
// the last chunk, which finalises and routes), and requires the 20k peak to stay within a constant of the
// 5k peak. A routing step that loaded every step would add roughly the plan size per 15,000 more rows.
func TestChunkedPlanMemoryBounded(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		peakOf := func(n int) (peak uint64, perChunk time.Duration) {
			p := newPRig(t, s, rigOpt{chunked: true})
			sub, err := p.r.SubmitDirectory(context.Background(), p.bulkReq(n))
			if err != nil {
				t.Fatal(err)
			}
			js := p.planJobs()
			var ms runtime.MemStats
			runtime.GC()
			runtime.ReadMemStats(&ms)
			base := ms.HeapAlloc
			start := time.Now()
			for _, a := range js {
				p.planChunk(sub.Operation, a)
				runtime.GC()
				runtime.ReadMemStats(&ms)
				if ms.HeapAlloc > base && ms.HeapAlloc-base > peak {
					peak = ms.HeapAlloc - base
				}
			}
			if st := p.opState(sub.Operation); st == "planning" {
				t.Fatalf("%d rows: plan not finalised", n)
			}
			return peak, time.Since(start) / time.Duration(len(js))
		}
		small, smallT := peakOf(5000)
		large, largeT := peakOf(20000)
		t.Logf("5000 rows: peak live heap +%d KiB, %v per chunk; 20000 rows: peak +%d KiB, %v per chunk",
			small>>10, smallT, large>>10, largeT)
		const slack = 4 << 20
		if large > small+slack {
			t.Fatalf("peak live heap grew with row count: 5000 rows +%d KiB, 20000 rows +%d KiB (slack %d KiB)", small>>10, large>>10, slack>>10)
		}
		if largeT > 3*smallT+50*time.Millisecond {
			t.Fatalf("per-chunk time grew with row count: %v vs %v", smallT, largeT)
		}
	})
}
