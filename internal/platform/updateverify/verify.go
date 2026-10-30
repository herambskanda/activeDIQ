package updateverify

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"slices"
	"time"
)

const (
	defaultMaxMetadata = 1 << 20 // endless-data defence for metadata files (spec section 3 rule 1)
	defaultClockSkew   = 5 * time.Minute
)

// Config builds a Verifier. Every consumer (server, connector, agent) pins its own root.
type Config struct {
	// PinnedRoot is the signed root metadata the caller trusts: the installer's root for a connector
	// or agent, the shipped root for the server. It is the only trust anchor.
	PinnedRoot []byte
	Floor      FloorStore
	Quarantine Quarantine
	// Name and Platform pin which component this consumer installs ("agent"/"windows"). They are
	// fixed here, never taken from the courier, so a compromised server or a crafted bundle cannot
	// steer a consumer to another genuinely signed release (TM-TB10-T5). Both are required.
	Name, Platform string
	// PlatformCheck verifies the Authenticode or OCI signature on the quarantined artefact. It runs
	// after hash and length pass and before Verify returns the path. It must not extract.
	PlatformCheck func(ctx context.Context, quarantinedPath string, rel Release) error
	// NoPlatformCheck must be set explicitly to run without PlatformCheck (tests, artefact kinds that
	// carry no platform signature). Forgetting it is a construction error, not a silent bypass.
	NoPlatformCheck bool
	Now             func() time.Time
	// MaxMetadataBytes bounds each metadata file; zero means 1 MiB.
	MaxMetadataBytes int64
	// ClockSkew is the tolerated lead of a signing time over the local clock; zero means 5 minutes.
	ClockSkew time.Duration
}

// Verifier is the update verifier. Calls must be serialised by the caller (one update decision at a time).
type Verifier struct {
	cfg  Config
	root *rootSigned
	rraw []byte
}

// New validates the pinned root (self-signed by its own threshold) and returns a Verifier.
func New(cfg Config) (*Verifier, error) {
	if cfg.Floor == nil || cfg.Quarantine == nil {
		return nil, errors.New("updateverify: Floor and Quarantine are required")
	}
	if cfg.Name == "" || cfg.Platform == "" {
		return nil, errors.New("updateverify: Name and Platform are required")
	}
	if cfg.PlatformCheck == nil && !cfg.NoPlatformCheck {
		return nil, errors.New("updateverify: PlatformCheck is required (or NoPlatformCheck set explicitly)")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.MaxMetadataBytes <= 0 {
		cfg.MaxMetadataBytes = defaultMaxMetadata
	}
	if cfg.ClockSkew <= 0 {
		cfg.ClockSkew = defaultClockSkew
	}
	env, r, err := decode[rootSigned](cfg.PinnedRoot, RoleRoot)
	if err != nil {
		return nil, fmt.Errorf("updateverify: pinned root: %w", err)
	}
	if err := validateRoot(r); err != nil || r.Type != RoleRoot {
		return nil, fmt.Errorf("updateverify: pinned root is invalid")
	}
	if sc := checkSignatures(env, r, RoleRoot, nil); len(sc.valid) < r.Roles[RoleRoot].Threshold {
		return nil, fmt.Errorf("updateverify: pinned root is not signed by its own threshold")
	}
	return &Verifier{cfg: cfg, root: r, rraw: cfg.PinnedRoot}, nil
}

// Input is what a courier hands over. Both couriers build the same Input; the verifier cannot tell
// them apart and must not.
type Input struct {
	// RootChain is the root metadata versions after the pinned one, ascending (an offline bundle
	// starts at the oldest root any supported install can hold; older entries are skipped).
	RootChain [][]byte
	Timestamp []byte
	Snapshot  []byte
	Targets   []byte
	// Artifact streams the artefact bytes.
	Artifact io.Reader
}

// Result is a fully verified release sitting in quarantine, plus facts for the audit event.
type Result struct {
	Release Release
	// Path of the verified artefact inside quarantine, for logs only. The apply mechanism must
	// consume the artefact through Open, never by reopening Path.
	Path string
	// SignerKeyIDs are the keys that signed each role's metadata, for update.verified.
	SignerKeyIDs map[string][]string
	// Versions of the metadata verified.
	RootVersion, TimestampVersion, SnapshotVersion, TargetsVersion uint64
	// NewestSigning is the newest signing time of the verified metadata.
	NewestSigning time.Time
}

// Verify decides whether in may be installed. On success the artefact is in quarantine; on failure
// nothing is left behind. A *Refusal means a security refusal; any other error means "not installed" too.
func (v *Verifier) Verify(ctx context.Context, in Input) (res *Result, err error) {
	now := v.cfg.Now()
	floor, err := v.cfg.Floor.Load(ctx)
	if err != nil {
		return nil, fmt.Errorf("updateverify: load floor: %w", err)
	}
	if now.Add(v.cfg.ClockSkew).Before(floor.NewestSigning) {
		return nil, refuse(ReasonFreeze, "", "system clock is earlier than the newest verified signing time")
	}

	root, revoked, rootVer, err := v.walkRoots(in.RootChain)
	if err != nil {
		return nil, err
	}
	if root.Version < floor.Root {
		return nil, refusef(ReasonRollback, RoleRoot, "root version %d below floor %d", root.Version, floor.Root)
	}
	if err := v.checkTime(&root.header, RoleRoot, now); err != nil {
		return nil, err
	}
	signers := map[string][]string{RoleRoot: rootVer}
	newest := root.Issued

	// timestamp
	tsRaw, err := v.limit(in.Timestamp, RoleTimestamp)
	if err != nil {
		return nil, err
	}
	ts, ids, err := verifyRole[timestampSigned](tsRaw, RoleTimestamp, root, revoked, func(s *timestampSigned) *header { return &s.header })
	if err != nil {
		return nil, err
	}
	signers[RoleTimestamp] = ids
	if ts.Version < floor.Timestamp {
		return nil, refusef(ReasonRollback, RoleTimestamp, "version %d below floor %d", ts.Version, floor.Timestamp)
	}
	if err := v.checkTime(&ts.header, RoleTimestamp, now); err != nil {
		return nil, err
	}
	newest = later(newest, ts.Issued)

	// snapshot
	snRaw, err := v.limit(in.Snapshot, RoleSnapshot)
	if err != nil {
		return nil, err
	}
	if err := matchRef(snRaw, ts.Snapshot, RoleSnapshot); err != nil {
		return nil, err
	}
	sn, ids, err := verifyRole[snapshotSigned](snRaw, RoleSnapshot, root, revoked, func(s *snapshotSigned) *header { return &s.header })
	if err != nil {
		return nil, err
	}
	signers[RoleSnapshot] = ids
	if sn.Version != ts.Snapshot.Version {
		return nil, refuse(ReasonTamper, RoleSnapshot, "version differs from the timestamp's reference")
	}
	if sn.Version < floor.Snapshot {
		return nil, refusef(ReasonRollback, RoleSnapshot, "version %d below floor %d", sn.Version, floor.Snapshot)
	}
	switch {
	case sn.RootVersion < root.Version:
		return nil, refusef(ReasonRollback, RoleSnapshot, "snapshot names root %d, chain is at %d", sn.RootVersion, root.Version)
	case sn.RootVersion > root.Version:
		return nil, refuse(ReasonTamper, RoleSnapshot, "snapshot names a root the chain did not supply")
	}
	if err := v.checkTime(&sn.header, RoleSnapshot, now); err != nil {
		return nil, err
	}
	newest = later(newest, sn.Issued)

	// targets
	tgRaw, err := v.limit(in.Targets, RoleTargets)
	if err != nil {
		return nil, err
	}
	if err := matchRef(tgRaw, sn.Targets, RoleTargets); err != nil {
		return nil, err
	}
	tg, ids, err := verifyRole[targetsSigned](tgRaw, RoleTargets, root, revoked, func(s *targetsSigned) *header { return &s.header })
	if err != nil {
		return nil, err
	}
	signers[RoleTargets] = ids
	if tg.Version != sn.Targets.Version {
		return nil, refuse(ReasonTamper, RoleTargets, "version differs from the snapshot's reference")
	}
	if tg.Version < floor.Targets {
		return nil, refusef(ReasonRollback, RoleTargets, "version %d below floor %d", tg.Version, floor.Targets)
	}
	if err := v.checkTime(&tg.header, RoleTargets, now); err != nil {
		return nil, err
	}
	newest = later(newest, tg.Issued)

	// All metadata is genuine and fresh: the floors may rise now, whatever happens to the artefact.
	raised := Floor{Root: root.Version, Timestamp: ts.Version, Snapshot: sn.Version, Targets: tg.Version, NewestSigning: newest}
	if err := v.cfg.Floor.Raise(ctx, raised); err != nil {
		return nil, fmt.Errorf("updateverify: persist floor: %w", err)
	}

	rel, err := pick(tg, v.cfg.Name, v.cfg.Platform)
	if err != nil {
		return nil, err
	}
	if rel.Withdrawn {
		return nil, refuse(ReasonWithdrawn, RoleTargets, "release is withdrawn")
	}
	if floor.Committed != "" {
		c, cerr := compareVersions(rel.ProductVersion, floor.Committed)
		if cerr != nil {
			return nil, refuse(ReasonTamper, RoleTargets, "product version is not valid")
		}
		if c < 0 {
			return nil, refusef(ReasonRollback, RoleTargets, "product version %s below committed %s", rel.ProductVersion, floor.Committed)
		}
	}
	if in.Artifact == nil {
		return nil, errors.New("updateverify: no artefact stream")
	}

	path, err := v.quarantine(ctx, in.Artifact, rel)
	if err != nil {
		return nil, err
	}
	return &Result{
		Release: rel, Path: path, SignerKeyIDs: signers,
		RootVersion: root.Version, TimestampVersion: ts.Version, SnapshotVersion: sn.Version, TargetsVersion: tg.Version,
		NewestSigning: newest,
	}, nil
}

// Commit records that the apply mechanism committed res's product version; the version floor rises
// and nothing below it can be offered again. Called by the apply mechanism (T-0553) after health passes.
func (v *Verifier) Commit(ctx context.Context, res *Result) error {
	if res == nil {
		return errors.New("updateverify: nil result")
	}
	return v.cfg.Floor.Raise(ctx, Floor{Committed: res.Release.ProductVersion})
}

func (v *Verifier) limit(b []byte, role string) ([]byte, error) {
	if int64(len(b)) > v.cfg.MaxMetadataBytes {
		return nil, refuse(ReasonTamper, role, "metadata exceeds the size limit")
	}
	if len(b) == 0 {
		return nil, refuse(ReasonTamper, role, "metadata missing")
	}
	return b, nil
}

func later(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}

// checkTime refuses expired metadata (freeze) and signing times ahead of the clock (clock rewound).
func (v *Verifier) checkTime(h *header, role string, now time.Time) error {
	if h.Expires.IsZero() || h.Issued.IsZero() {
		return refuse(ReasonTamper, role, "issued or expires missing")
	}
	if !now.Before(h.Expires) {
		return &Refusal{Reason: ReasonFreeze, Role: role, Detail: "metadata expired", Expiry: h.Expires}
	}
	if h.Issued.After(now.Add(v.cfg.ClockSkew)) {
		return refuse(ReasonFreeze, role, "signing time is ahead of the system clock")
	}
	return nil
}

func matchRef(raw []byte, ref fileRef, role string) error {
	if int64(len(raw)) != ref.Length {
		return refuse(ReasonTamper, role, "length differs from the signed reference")
	}
	h := sha256.Sum256(raw)
	want, err := hex.DecodeString(ref.SHA256)
	if err != nil || len(want) != sha256.Size || subtle.ConstantTimeCompare(h[:], want) != 1 {
		return refuse(ReasonTamper, role, "hash differs from the signed reference")
	}
	return nil
}

// verifyRole decodes a metadata file of role and checks its threshold of signatures against root.
func verifyRole[T any](raw []byte, role string, root *rootSigned, revoked revokedSet, h func(*T) *header) (*T, []string, error) {
	env, s, err := decode[T](raw, role)
	if err != nil {
		return nil, nil, err
	}
	if h(s).Type != role {
		return nil, nil, refuse(ReasonTamper, role, "metadata type differs from its role")
	}
	sc := checkSignatures(env, root, role, revoked)
	if len(sc.valid) < root.Roles[role].Threshold {
		if len(sc.revoked) > 0 {
			return nil, nil, refuse(ReasonRevokedKey, role, "signed by a key a later root removed")
		}
		return nil, nil, refuse(ReasonUnsignedByRoot, role, "signatures do not reach the role's threshold")
	}
	return s, sc.valid, nil
}

// walkRoots applies the chain on top of the pinned root. Each root is accepted only if signed by the
// previous root's root-role threshold and by its own (spec section 3 rule 5).
func (v *Verifier) walkRoots(chain [][]byte) (*rootSigned, revokedSet, []string, error) {
	cur := v.root
	revoked := revokedSet{}
	curSigners := checkSignatures(mustEnv(v.rraw), cur, RoleRoot, nil).valid
	for _, raw := range chain {
		if int64(len(raw)) > v.cfg.MaxMetadataBytes {
			return nil, nil, nil, refuse(ReasonTamper, RoleRoot, "metadata exceeds the size limit")
		}
		env, next, err := decode[rootSigned](raw, RoleRoot)
		if err != nil {
			return nil, nil, nil, err
		}
		if next.Version <= cur.Version {
			continue // already behind the trusted root
		}
		if next.Type != RoleRoot || validateRoot(next) != nil {
			return nil, nil, nil, refuse(ReasonTamper, RoleRoot, "root is not valid")
		}
		if next.Version != cur.Version+1 {
			return nil, nil, nil, refusef(ReasonUnsignedByRoot, RoleRoot, "root chain skips from %d to %d", cur.Version, next.Version)
		}
		// Keys removed from a role by this root are revoked for that role, for good.
		nextRevoked := revokedSet{}
		for role, set := range revoked {
			nextRevoked[role] = map[string]ed25519.PublicKey{}
			for id, pk := range set {
				nextRevoked[role][id] = pk
			}
		}
		for _, role := range roles {
			if nextRevoked[role] == nil {
				nextRevoked[role] = map[string]ed25519.PublicKey{}
			}
			for _, id := range cur.Roles[role].KeyIDs {
				if !slices.Contains(next.Roles[role].KeyIDs, id) {
					pk, _ := parseKey(id, cur.Keys[id])
					nextRevoked[role][id] = pk
				}
			}
			for _, id := range next.Roles[role].KeyIDs {
				if _, gone := nextRevoked[role][id]; gone {
					return nil, nil, nil, refusef(ReasonRevokedKey, RoleRoot, "root re-adds a revoked key to %s", role)
				}
			}
		}
		oldSC := checkSignatures(env, cur, RoleRoot, revoked)
		if len(oldSC.valid) < cur.Roles[RoleRoot].Threshold {
			if len(oldSC.revoked) > 0 {
				return nil, nil, nil, refuse(ReasonRevokedKey, RoleRoot, "new root signed by a revoked key")
			}
			return nil, nil, nil, refuse(ReasonUnsignedByRoot, RoleRoot, "new root lacks the old root's threshold")
		}
		newSC := checkSignatures(env, next, RoleRoot, nil)
		if len(newSC.valid) < next.Roles[RoleRoot].Threshold {
			return nil, nil, nil, refuse(ReasonUnsignedByRoot, RoleRoot, "new root lacks its own threshold")
		}
		cur, revoked, curSigners = next, nextRevoked, newSC.valid
	}
	return cur, revoked, curSigners, nil
}

func mustEnv(raw []byte) *envelope {
	env, _, _ := decode[rootSigned](raw, RoleRoot) // validated in New
	return env
}

func pick(t *targetsSigned, name, platform string) (Release, error) {
	var found []Release
	for _, r := range t.Releases {
		if r.Name == name && r.Platform == platform {
			found = append(found, r)
		}
	}
	if len(found) != 1 {
		return Release{}, refuse(ReasonTamper, RoleTargets, "release is not listed exactly once in the signed manifest")
	}
	r := found[0]
	if r.Length < 0 {
		return Release{}, refuse(ReasonTamper, RoleTargets, "negative length")
	}
	if _, err := parseVersion(r.ProductVersion); err != nil {
		return Release{}, refuse(ReasonTamper, RoleTargets, "product version is not valid")
	}
	return r, nil
}

// quarantine streams the artefact to quarantine, aborting as soon as it exceeds its signed length, and
// returns the path only when length, hash and the platform signature pass.
func (v *Verifier) quarantine(ctx context.Context, src io.Reader, rel Release) (path string, err error) {
	want, derr := hex.DecodeString(rel.SHA256)
	if derr != nil || len(want) != sha256.Size {
		return "", refuse(ReasonTamper, RoleTargets, "release hash is not valid")
	}
	f, err := v.cfg.Quarantine.Create()
	if err != nil {
		return "", fmt.Errorf("updateverify: quarantine: %w", err)
	}
	defer func() {
		if err != nil {
			_ = f.Remove()
		}
	}()
	h := sha256.New()
	// Read at most length+1 bytes: one byte more than signed proves the artefact is too long.
	n, cerr := io.Copy(io.MultiWriter(f, h), io.LimitReader(&ctxReader{ctx, src}, rel.Length+1))
	if cerr != nil {
		return "", fmt.Errorf("updateverify: reading artefact: %w", cerr)
	}
	if n > rel.Length {
		return "", refuse(ReasonTamper, "artefact", "longer than its signed length")
	}
	if n != rel.Length {
		return "", refuse(ReasonTamper, "artefact", "shorter than its signed length")
	}
	if subtle.ConstantTimeCompare(h.Sum(nil), want) != 1 {
		return "", refuse(ReasonTamper, "artefact", "hash differs from the signed manifest")
	}
	if err := f.Close(); err != nil {
		return "", fmt.Errorf("updateverify: quarantine: %w", err)
	}
	if v.cfg.PlatformCheck != nil {
		if perr := v.cfg.PlatformCheck(ctx, f.Path(), rel); perr != nil {
			var r *Refusal
			if errors.As(perr, &r) {
				return "", perr
			}
			return "", refuse(ReasonTamper, "artefact", "platform signature check failed")
		}
	}
	return f.Path(), nil
}

type ctxReader struct {
	ctx context.Context
	r   io.Reader
}

func (c *ctxReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.r.Read(p)
}
