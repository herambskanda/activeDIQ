package migration

import (
	"context"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"

	"github.com/skenzeriq/activediq/internal/platform/operation/step"
	"github.com/skenzeriq/activediq/internal/platform/store"
)

// jobState reads the state of a job of the transaction's tenant.
func jobState(ctx context.Context, tx store.Tx, jobID string) (string, bool, error) {
	var st string
	err := tx.QueryRow(ctx, `SELECT state FROM public.migration_jobs WHERE job_id = $1::uuid`, jobID).Scan(&st)
	if store.IsNoRows(err) {
		return "", false, nil
	}
	return st, err == nil, err
}

// insertFidelity writes the fidelity rows and the proposals of one job in the step's transaction. The
// arrays are parameters; no SQL text is built from item content. A second record for the same job (or a
// repeated item ref) violates a unique key and returns ErrAlreadyRecorded.
func insertFidelity(ctx context.Context, s step.Step, tenantID, jobID string, rows []Classified) error {
	tx := s.Tx()
	if tx == nil {
		return errors.New("migration: no step transaction")
	}
	n := len(rows)
	seq, ref, kind, name := make([]int32, n), make([]string, n), make([]string, n), make([]string, n)
	class, reason, diff, detail := make([]string, n), make([]string, n), make([]string, n), make([]string, n)
	var pSeq []int32
	var pClass, pConfig, pGrants []string
	for i, c := range rows {
		seq[i], ref[i], kind[i], name[i] = int32(c.Seq), c.Item.Ref, c.Item.Kind, c.Item.Name
		class[i], reason[i], detail[i] = string(c.Class), c.Reason, c.Detail
		d := c.Item.Diff
		if d == nil || c.Class != ClassChanged {
			d = []DiffEntry{}
		}
		b, err := jsonv2.Marshal(d)
		if err != nil {
			return fmt.Errorf("migration: encode diff: %w", err)
		}
		diff[i] = string(b)
		if c.Proposal != nil {
			g, err := jsonv2.Marshal(c.Proposal.Grants)
			if err != nil {
				return fmt.Errorf("migration: encode grants: %w", err)
			}
			pSeq, pClass = append(pSeq, int32(c.Seq)), append(pClass, string(c.Class))
			pConfig, pGrants = append(pConfig, string(c.Proposal.Config)), append(pGrants, string(g))
		}
	}
	_, err := tx.Exec(ctx, `INSERT INTO public.migration_fidelity
		(tenant_id, job_id, item_seq, item_ref, item_kind, item_name, class, reason, diff, detail)
		SELECT $1::uuid, $2::uuid, u.seq, u.ref, u.kind, u.name, u.class, u.reason, u.diff::jsonb, u.detail
		FROM unnest($3::int[], $4::text[], $5::text[], $6::text[], $7::text[], $8::text[], $9::text[], $10::text[])
		  AS u(seq, ref, kind, name, class, reason, diff, detail)`,
		tenantID, jobID, seq, ref, kind, name, class, reason, diff, detail)
	if err != nil {
		return recordErr("fidelity", err)
	}
	if len(pSeq) == 0 {
		return nil
	}
	_, err = tx.Exec(ctx, `INSERT INTO public.migration_proposals (tenant_id, job_id, item_seq, class, config, grants)
		SELECT $1::uuid, $2::uuid, u.seq, u.class, u.config::jsonb, u.grants::jsonb
		FROM unnest($3::int[], $4::text[], $5::text[], $6::text[]) AS u(seq, class, config, grants)`,
		tenantID, jobID, pSeq, pClass, pConfig, pGrants)
	if err != nil {
		return recordErr("proposals", err)
	}
	return nil
}

func recordErr(what string, err error) error {
	if store.SQLState(err) == "23505" {
		return ErrAlreadyRecorded
	}
	return fmt.Errorf("migration: insert %s: %w", what, err)
}

// counts returns the stored rows of a job per class, and its proposal count.
func counts(ctx context.Context, tx store.Tx, jobID string) (byClass map[string]int, proposals int, err error) {
	byClass = map[string]int{}
	rows, err := tx.Query(ctx, `SELECT class, count(*)::int FROM public.migration_fidelity WHERE job_id = $1::uuid GROUP BY class`, jobID)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	for rows.Next() {
		var c string
		var n int
		if err := rows.Scan(&c, &n); err != nil {
			return nil, 0, err
		}
		byClass[c] = n
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	err = tx.QueryRow(ctx, `SELECT count(*)::int FROM public.migration_proposals WHERE job_id = $1::uuid`, jobID).Scan(&proposals)
	return byClass, proposals, err
}

// FidelityRow is one stored row of the report.
type FidelityRow struct {
	Seq                            int
	Ref, Kind, Name, Class, Reason string
	Diff                           []DiffEntry
	Detail                         string
	HasProposal                    bool
}

// listFidelity streams the rows of a job in item order through fn.
func listFidelity(ctx context.Context, tx store.Tx, jobID string, fn func(FidelityRow) error) error {
	rows, err := tx.Query(ctx, `SELECT f.item_seq, f.item_ref, f.item_kind, f.item_name, f.class, f.reason, f.diff::text, f.detail,
			(p.proposal_id IS NOT NULL)
		FROM public.migration_fidelity f
		LEFT JOIN public.migration_proposals p ON p.tenant_id = f.tenant_id AND p.job_id = f.job_id AND p.item_seq = f.item_seq
		WHERE f.job_id = $1::uuid ORDER BY f.item_seq`, jobID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var r FidelityRow
		var diff string
		if err := rows.Scan(&r.Seq, &r.Ref, &r.Kind, &r.Name, &r.Class, &r.Reason, &diff, &r.Detail, &r.HasProposal); err != nil {
			return err
		}
		if err := jsonv2.Unmarshal([]byte(diff), &r.Diff); err != nil {
			return fmt.Errorf("migration: stored diff unreadable: %w", err)
		}
		if err := fn(r); err != nil {
			return err
		}
	}
	return rows.Err()
}
