package connection

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/store"
)

const verificationColumns = `id, connection_id, credential_id, kind, requested_by, started_at, completed_at,
	observed_identity, check_list_version, outcomes, verdict, findings_digest`

func scanVerification(r scanner) (Verification, error) {
	var v Verification
	var id, conn, cred, kind, ident, verdict string
	var outcomes []byte
	if err := r.Scan(&id, &conn, &cred, &kind, &v.RequestedBy, &v.StartedAt, &v.CompletedAt,
		&ident, &v.CheckListVersion, &outcomes, &verdict, &v.FindingsDigest); err != nil {
		return Verification{}, err
	}
	raw := map[string]string{}
	if err := json.Unmarshal(outcomes, &raw); err != nil {
		return Verification{}, fmt.Errorf("outcomes: %w", err)
	}
	v.Outcomes = make(map[Check]Outcome, len(raw))
	for c, o := range raw {
		v.Outcomes[Check(c)] = Outcome(o)
	}
	v.ID, v.ConnectionID, v.CredentialID = VerificationID(id), ID(conn), CredentialID(cred)
	v.Kind, v.ObservedIdentity, v.Verdict = VerificationKind(kind), DirectoryIdentity(ident), Verdict(verdict)
	return v, nil
}

// RecordVerification inserts a completed run with its findings (DM-24.I1) and, in the same
// transaction, moves the connection's verification pointer (DM-10.I8): last_verification_id names
// this run, and verified_at is its completion time on a pass and empty otherwise, so a refusal after
// a pass leaves nothing to activate on. completed_at is the connection's next ordering stamp, so the
// run, an override and a retirement of one connection are strictly ordered (DM-10.I13).
//
// It does not change the lifecycle state: the caller decides that from the run (I10). A
// credential_change run needs the credential port (DM-11) and is refused until it lands.
func (Store) RecordVerification(ctx context.Context, tx store.Tx, n NewVerification) (Verification, error) {
	if err := n.validate(); err != nil {
		return Verification{}, err
	}
	if n.Kind == KindCredentialChange {
		return Verification{}, fmt.Errorf("%w: credential_change runs arrive with the credential port", ErrInvalid)
	}
	cur, stamp, err := lock(ctx, tx, n.ConnectionID)
	if err != nil {
		return Verification{}, err
	}
	if cur.CredentialID != n.CredentialID {
		return Verification{}, fmt.Errorf("%w: the run verified a credential the connection does not use", ErrInvalid)
	}
	if cur.State.Terminal() || cur.State == StateDecommissioning {
		return Verification{}, fmt.Errorf("%w: a %s connection is not verified", ErrIllegalTransition, cur.State)
	}
	started := n.StartedAt
	if started.After(stamp) {
		started = stamp // a skewed caller clock cannot put the start after the completion
	}
	outcomes := make(map[string]string, len(n.Outcomes))
	for c, o := range n.Outcomes {
		outcomes[string(c)] = string(o)
	}
	ob, err := json.Marshal(outcomes)
	if err != nil {
		return Verification{}, fmt.Errorf("connection: record verification: %w", err)
	}
	fps := make([]string, len(n.Findings))
	for i, f := range n.Findings {
		fps[i] = f.Fingerprint
	}
	salt := newSalt()
	row := tx.QueryRow(ctx, `INSERT INTO public.connection_verifications
		(tenant_id, id, connection_id, credential_id, kind, requested_by, started_at, completed_at,
		 observed_identity, check_list_version, outcomes, verdict, digest_salt, findings_digest)
		VALUES (NULLIF(current_setting('app.tenant_id', true), '')::uuid, $1::uuid, $2::uuid, $3::uuid, $4, $5, $6, $7,
		 $8, $9, $10::jsonb, $11, $12, $13)
		RETURNING `+verificationColumns,
		string(n.ID), string(n.ConnectionID), string(n.CredentialID), string(n.Kind), n.RequestedBy, started, stamp,
		string(n.ObservedIdentity), n.CheckListVersion, string(ob), string(n.Verdict), salt, findingsDigest(salt, fps))
	v, err := scanVerification(row)
	if err != nil {
		return Verification{}, fmt.Errorf("connection: record verification: %w", err)
	}
	if len(n.Findings) > 0 {
		if err := insertFindings(ctx, tx, n.ID, n.Findings); err != nil {
			return Verification{}, err
		}
	}
	var verifiedAt *time.Time
	if n.Verdict == VerdictPass {
		verifiedAt = &stamp
	}
	tag, err := tx.Exec(ctx, `UPDATE public.connections SET last_verification_id = $2::uuid, verified_at = $3,
		last_stamp_at = $4, updated_at = now() WHERE id = $1::uuid`, string(n.ConnectionID), string(n.ID), verifiedAt, stamp)
	if err != nil || tag.RowsAffected() != 1 {
		return Verification{}, fmt.Errorf("connection: record verification: moving the pointer: %w", errOrNoRow(err))
	}
	v.Findings = append([]Finding(nil), n.Findings...)
	return v, nil
}

func errOrNoRow(err error) error {
	if err != nil {
		return err
	}
	return ErrNotFound
}

// insertFindings stores a run's findings in one statement. Parameterised arrays, never text built
// from the values.
func insertFindings(ctx context.Context, tx store.Tx, id VerificationID, fs []Finding) error {
	n := len(fs)
	ord, chk, code, kind, sev := make([]int32, n), make([]string, n), make([]string, n), make([]string, n), make([]string, n)
	obj, sid, qual, fp := make([]string, n), make([]string, n), make([]string, n), make([]string, n)
	for i, f := range fs {
		ord[i], chk[i], code[i], kind[i], sev[i] = int32(i), string(f.Check), f.Code, string(f.Kind), string(f.Severity)
		obj[i], sid[i], qual[i], fp[i] = f.ObjectGUID, f.ObjectDomainSID, f.Qualifier, f.Fingerprint
	}
	_, err := tx.Exec(ctx, `INSERT INTO public.connection_verification_findings
		(tenant_id, verification_id, ordinal, check_name, code, kind, severity, object_guid, object_domain_sid, qualifier, fingerprint)
		SELECT NULLIF(current_setting('app.tenant_id', true), '')::uuid, $1::uuid, o, c, cd, k, s, g, d, q, f
		FROM unnest($2::int[], $3::text[], $4::text[], $5::text[], $6::text[], $7::text[], $8::text[], $9::text[], $10::text[])
		  AS t(o, c, cd, k, s, g, d, q, f)`,
		string(id), ord, chk, code, kind, sev, obj, sid, qual, fp)
	if err != nil {
		return fmt.Errorf("connection: record findings: %w", err)
	}
	return nil
}

func loadFindings(ctx context.Context, tx store.Tx, id VerificationID) ([]Finding, error) {
	rows, err := tx.Query(ctx, `SELECT check_name, code, kind, severity, object_guid, object_domain_sid, qualifier, fingerprint
		FROM public.connection_verification_findings WHERE verification_id = $1::uuid ORDER BY ordinal LIMIT $2`, string(id), maxFindings)
	if err != nil {
		return nil, fmt.Errorf("connection: findings: %w", err)
	}
	defer rows.Close()
	var out []Finding
	for rows.Next() {
		var f Finding
		var chk, kind, sev string
		if err := rows.Scan(&chk, &f.Code, &kind, &sev, &f.ObjectGUID, &f.ObjectDomainSID, &f.Qualifier, &f.Fingerprint); err != nil {
			return nil, fmt.Errorf("connection: findings: %w", err)
		}
		f.Check, f.Kind, f.Severity = Check(chk), FindingKind(kind), Severity(sev)
		out = append(out, f)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("connection: findings: %w", err)
	}
	return out, nil
}

// GetVerification returns one run of a connection, with its findings when withFindings. Findings
// enumerate Tier-0 exposure (FR-16): the caller passes true only for an account that may start a
// verification on the connection. The tenant is the transaction's.
func (Store) GetVerification(ctx context.Context, tx store.Tx, conn ID, id VerificationID, withFindings bool) (Verification, error) {
	if err := requireTenant(ctx, tx); err != nil {
		return Verification{}, err
	}
	if _, err := ParseID(string(conn)); err != nil {
		return Verification{}, err
	}
	if _, err := ParseVerificationID(string(id)); err != nil {
		return Verification{}, err
	}
	return getVerification(ctx, tx, conn, id, withFindings)
}

func getVerification(ctx context.Context, tx store.Tx, conn ID, id VerificationID, withFindings bool) (Verification, error) {
	v, err := scanVerification(tx.QueryRow(ctx, `SELECT `+verificationColumns+` FROM public.connection_verifications
		WHERE connection_id = $1::uuid AND id = $2::uuid`, string(conn), string(id)))
	if store.IsNoRows(err) {
		return Verification{}, ErrVerificationNotFound
	}
	if err != nil {
		return Verification{}, fmt.Errorf("connection: get verification: %w", err)
	}
	if withFindings {
		if v.Findings, err = loadFindings(ctx, tx, v.ID); err != nil {
			return Verification{}, err
		}
	}
	return v, nil
}

// FindingCount returns how many findings a run has, for the readers who may see counts only.
func (Store) FindingCount(ctx context.Context, tx store.Tx, id VerificationID) (int, error) {
	if err := requireTenant(ctx, tx); err != nil {
		return 0, err
	}
	var n int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM public.connection_verification_findings WHERE verification_id = $1::uuid`, string(id)).Scan(&n); err != nil {
		return 0, fmt.Errorf("connection: finding count: %w", err)
	}
	return n, nil
}
