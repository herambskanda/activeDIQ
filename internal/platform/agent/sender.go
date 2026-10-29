package agent

import (
	"context"
	"math/rand/v2"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	agentv1 "github.com/skenzeriq/activediq/internal/proto/skenzeriq/agent/v1"
)

// The sender drains the outbox to EventIngest.SubmitEvents at least once. It never runs inside a
// module's event path; a down tunnel, a slow server or a refusing server only makes the outbox grow
// to its bound.
const (
	maxBatchRecords = 1000 // agentingest.MaxBatchRecords; the server refuses more
	sendTimeout     = 30 * time.Second
	flushEvery      = time.Second
	idleEvery       = time.Second
	backoffMin      = time.Second
	backoffMax      = time.Minute
)

func (h *Host) currentClient() agentv1.EventIngestClient {
	h.sendMu.Lock()
	defer h.sendMu.Unlock()
	return h.client
}

func (h *Host) batchBytes() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.policy != nil {
		return int(h.policy.Events.BatchMaxBytes)
	}
	return int(h.cfg.Ceilings.BatchMaxBytes)
}

func (h *Host) sendLoop(ctx context.Context) {
	backoff := time.Duration(0)
	t := time.NewTimer(idleEvery)
	defer t.Stop()
	lastFlush := time.Now()
	for {
		select {
		case <-ctx.Done():
			_ = h.outbox.Flush()
			return
		case <-t.C:
		case <-h.wake:
		}
		if time.Since(lastFlush) >= flushEvery {
			if err := h.outbox.Flush(); err != nil {
				h.log.Warn("outbox flush failed", "err", err)
			}
			lastFlush = time.Now()
		}
		wait := idleEvery
		if cl := h.currentClient(); cl != nil {
			more, err := h.sendOnce(ctx, cl)
			switch {
			case err != nil:
				backoff = min(max(backoff*2, backoffMin), backoffMax)
				wait = backoff/2 + rand.N(backoff/2+1)
			case more:
				backoff, wait = 0, 0
			default:
				backoff = 0
			}
		}
		t.Reset(max(wait, time.Millisecond))
	}
}

// sendOnce delivers one batch. more is true when the outbox probably holds further records.
func (h *Host) sendOnce(ctx context.Context, cl agentv1.EventIngestClient) (more bool, err error) {
	batch, err := h.outbox.Next(maxBatchRecords, h.batchBytes())
	if err != nil {
		h.log.Warn("outbox read failed", "err", err)
		return false, err
	}
	if len(batch) == 0 {
		return false, nil
	}
	for len(batch) > 0 {
		cctx, cancel := context.WithTimeout(ctx, sendTimeout)
		resp, err := cl.SubmitEvents(cctx, &agentv1.SubmitEventsRequest{Events: batch})
		cancel()
		if err == nil {
			// The server is trusted to report what it stored; never ack past what this batch carried.
			h.outbox.Ack(min(resp.GetHighestStoredSeq(), batch[len(batch)-1].GetAgentSeq()))
			return true, nil
		}
		if status.Code(err) != codes.InvalidArgument {
			return false, err
		}
		// The server refused the batch as malformed. One bad record must not wedge the queue behind
		// it: halve until the offender is alone, then drop it and say so.
		if len(batch) == 1 {
			h.log.Error("server refused a record as invalid; dropping it", "agent_seq", batch[0].GetAgentSeq())
			h.outbox.Ack(batch[0].GetAgentSeq())
			h.outbox.noteDropped(1)
			return true, nil
		}
		batch = batch[:len(batch)/2]
	}
	return false, nil
}
