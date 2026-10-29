package connection

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/audit/canon"
	"github.com/skenzeriq/activediq/internal/platform/tablekind"
)

// The DM-24 and DM-25 tables. Findings and overrides are children of the verification and the
// connection, so they carry the same tenant key and are declared for fitness-domain-keys the same way.
var (
	verificationsTable = tablekind.Declare(tablekind.Table{
		Name: "public.connection_verifications", Entity: "DM-24", Kind: tablekind.Tenant, AppendOnly: true,
	})
	findingsTable = tablekind.Declare(tablekind.Table{
		Name: "public.connection_verification_findings", Entity: "DM-24", Kind: tablekind.Tenant, AppendOnly: true,
	})
	overridesTable = tablekind.Declare(tablekind.Table{
		Name: "public.connection_tier0_overrides", Entity: "DM-25", Kind: tablekind.Tenant, AppendOnly: true,
	})
)

// VerificationID identifies a DM-24 run. The server draws it before the run starts, so the connector
// can echo it, and it becomes the row's ID.
type VerificationID string

// ParseVerificationID accepts a canonical UUID (either case) and returns it lower-cased.
func ParseVerificationID(s string) (VerificationID, error) {
	v, ok := canonUUID(s)
	if !ok {
		return "", ErrInvalid
	}
	return VerificationID(v), nil
}

// VerificationKind is why a run happened (DM-24 kind).
type VerificationKind string

// The run kinds. onboarding and activation start from a draft; the rest are jobs on a live connection.
const (
	KindOnboarding       VerificationKind = "onboarding"
	KindActivation       VerificationKind = "activation"
	KindResume           VerificationKind = "resume"
	KindCredentialChange VerificationKind = "credential_change"
	KindScheduled        VerificationKind = "scheduled"
	KindManual           VerificationKind = "manual"
)

func (k VerificationKind) valid() bool {
	switch k {
	case KindOnboarding, KindActivation, KindResume, KindCredentialChange, KindScheduled, KindManual:
		return true
	}
	return false
}

// Check names one check of a run: V1…V9 for an AD forest, EV1…EV5 for an Entra tenant.
type Check string

// Checks the server's rules name. Others are carried as data (outcomes), never branched on.
const (
	CheckV7OverPrivilege  Check = "V7"
	CheckV8ReadSufficient Check = "V8"
	CheckEV3OverPrivilege Check = "EV3"
	CheckEV4Sufficiency   Check = "EV4"
)

var checkName = regexp.MustCompile(`^(V[1-9]|EV[1-5])$`)

// overPrivilegeCheck is the check whose failure an override may cover (TM-D1): V7 for AD, EV3 for
// Entra. The same shape serves both kinds; only the name differs.
func overPrivilegeCheck(k Kind) Check {
	if k == KindEntraTenant {
		return CheckEV3OverPrivilege
	}
	return CheckV7OverPrivilege
}

// readSufficiencyCheck is the check that the identity can read what the product needs: V8 for AD,
// EV4 for Entra.
func readSufficiencyCheck(k Kind) Check {
	if k == KindEntraTenant {
		return CheckEV4Sufficiency
	}
	return CheckV8ReadSufficient
}

// requiredForPass lists the checks a pass verdict must answer with a pass or warn outcome: identity,
// over-privilege and read sufficiency. A pass that lacks one (a connector bug, a check-list version
// skew, a remote connector that dropped it) must not open any gate.
func requiredForPass(k Kind) []Check {
	return []Check{identityCheck(k), overPrivilegeCheck(k), readSufficiencyCheck(k)}
}

// passComplete reports whether a pass verdict is backed by an answered outcome for every required
// check and carries no not_run outcome.
func passComplete(k Kind, outcomes map[Check]Outcome) bool {
	for _, o := range outcomes {
		if o == OutcomeNotRun {
			return false
		}
	}
	for _, c := range requiredForPass(k) {
		o := outcomes[c]
		if o != OutcomePass && (o != OutcomeWarn || c == overPrivilegeCheck(k)) {
			return false // the over-privilege check must be a clean pass, as the gate requires
		}
	}
	return true
}

// Outcome is the result of one check.
type Outcome string

// The check outcomes.
const (
	OutcomePass           Outcome = "pass"
	OutcomeWarn           Outcome = "warn"
	OutcomeFail           Outcome = "fail"
	OutcomeCouldNotVerify Outcome = "could_not_verify"
	OutcomeNotRun         Outcome = "not_run"
)

func (o Outcome) valid() bool {
	switch o {
	case OutcomePass, OutcomeWarn, OutcomeFail, OutcomeCouldNotVerify, OutcomeNotRun:
		return true
	}
	return false
}

// Verdict summarises a run (DM-24.I2).
type Verdict string

// The verdicts. `refused` is the one an override can reach, and only for the over-privilege check.
const (
	VerdictPass           Verdict = "pass"
	VerdictRefused        Verdict = "refused"
	VerdictCouldNotVerify Verdict = "could_not_verify"
	VerdictFailed         Verdict = "failed"
)

func (v Verdict) valid() bool {
	switch v {
	case VerdictPass, VerdictRefused, VerdictCouldNotVerify, VerdictFailed:
		return true
	}
	return false
}

// Severity of a finding.
type Severity string

// The finding severities.
const (
	SeverityBlock Severity = "block"
	SeverityWarn  Severity = "warn"
	SeverityInfo  Severity = "info"
)

// FindingKind says what a finding is about. Health reports on the first two every run (TM-D1); the
// rest are carried as registered strings.
type FindingKind string

// The two halves of rights drift.
const (
	FindingExcessiveRight FindingKind = "excessive_right"
	FindingMissingRight   FindingKind = "missing_right"
)

var (
	codeText = regexp.MustCompile(`^[a-z0-9_.]{1,64}$`)
	sidText  = regexp.MustCompile(`^S-1-[0-9]+(-[0-9]+)+$`)
	hex64    = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// Finding is one DM-24 Finding. It holds identifiers only (DM-24.I3): no DN, name, UPN or display
// value, no secret. Reading findings needs the verify permission (FR-16); the rest of the system
// sees counts.
type Finding struct {
	Check           Check
	Code            string
	Kind            FindingKind
	Severity        Severity
	ObjectGUID      string // canonical lower-case UUID text, or empty
	ObjectDomainSID string // a SID, or empty
	Qualifier       string // a GUID or a SID, or empty
	Fingerprint     string // lower-case hex SHA-256 computed by the connector (DM-24.I4)
}

func (f Finding) validate() error {
	if !checkName.MatchString(string(f.Check)) || !codeText.MatchString(f.Code) || !codeText.MatchString(string(f.Kind)) {
		return fmt.Errorf("%w: finding check, code or kind", ErrInvalid)
	}
	switch f.Severity {
	case SeverityBlock, SeverityWarn, SeverityInfo:
	default:
		return fmt.Errorf("%w: finding severity", ErrInvalid)
	}
	if f.ObjectGUID != "" {
		if v, ok := canonUUID(f.ObjectGUID); !ok || v != f.ObjectGUID {
			return fmt.Errorf("%w: finding object guid", ErrInvalid)
		}
	}
	if f.ObjectDomainSID != "" && !sidText.MatchString(f.ObjectDomainSID) {
		return fmt.Errorf("%w: finding domain sid", ErrInvalid)
	}
	if f.Qualifier != "" {
		v, ok := canonUUID(f.Qualifier)
		if !(ok && v == f.Qualifier) && !sidText.MatchString(f.Qualifier) {
			return fmt.Errorf("%w: finding qualifier", ErrInvalid)
		}
	}
	if !hex64.MatchString(f.Fingerprint) {
		return fmt.Errorf("%w: finding fingerprint", ErrInvalid)
	}
	return nil
}

// maxFindings bounds one run. Findings are bounded by the Tier-0 set and the managed OU count
// (DM-24.I7); a run past this is a defect in the connector, not a result to store.
const maxFindings = 50000

// Verification is a stored DM-24 run, with its findings when they were read.
type Verification struct {
	ID               VerificationID
	ConnectionID     ID
	CredentialID     CredentialID
	Kind             VerificationKind
	RequestedBy      string // pseudonymous principal ID; empty for a scheduled run
	StartedAt        time.Time
	CompletedAt      time.Time // the connection's ordering stamp at insert (DM-10.I13)
	ObservedIdentity DirectoryIdentity
	CheckListVersion int
	Outcomes         map[Check]Outcome
	Verdict          Verdict
	FindingsDigest   []byte // salted, so a reader without the findings cannot recompute it (DM-24.I5)
	Findings         []Finding
}

// Outcome returns one check's outcome, or "" when the run has none for it.
func (v Verification) Outcome(c Check) Outcome { return v.Outcomes[c] }

// NewVerification is what RecordVerification needs: a completed run, as the connector reported it.
type NewVerification struct {
	ID               VerificationID // drawn by the caller before the run starts
	ConnectionID     ID
	CredentialID     CredentialID
	Kind             VerificationKind
	RequestedBy      string
	StartedAt        time.Time
	ObservedIdentity DirectoryIdentity
	CheckListVersion int
	Outcomes         map[Check]Outcome
	Verdict          Verdict
	Findings         []Finding
}

func (n NewVerification) validate() error {
	if _, err := ParseVerificationID(string(n.ID)); err != nil {
		return err
	}
	if _, err := ParseID(string(n.ConnectionID)); err != nil {
		return err
	}
	if _, ok := canonUUID(string(n.CredentialID)); !ok {
		return fmt.Errorf("%w: credential id", ErrInvalid)
	}
	if !n.Kind.valid() || !n.Verdict.valid() || n.StartedAt.IsZero() || n.CheckListVersion < 1 {
		return fmt.Errorf("%w: verification kind, verdict, start time or check list version", ErrInvalid)
	}
	if (n.Kind == KindScheduled) != (n.RequestedBy == "") {
		return fmt.Errorf("%w: only a scheduled run has no requester", ErrInvalid)
	}
	if n.ObservedIdentity != "" {
		if _, err := ParseDirectoryIdentity(string(n.ObservedIdentity)); err != nil {
			return err
		}
	}
	if len(n.Outcomes) == 0 {
		return fmt.Errorf("%w: a run records an outcome per check", ErrInvalid)
	}
	var fail, cnv bool
	for c, o := range n.Outcomes {
		if !checkName.MatchString(string(c)) || !o.valid() {
			return fmt.Errorf("%w: check outcome", ErrInvalid)
		}
		fail = fail || o == OutcomeFail
		cnv = cnv || o == OutcomeCouldNotVerify
	}
	// A pass that hides a failed or unanswered check would open the gates; refuse it here, whatever
	// the connector said. The database cannot see inside the JSON, so this is the guard.
	if n.Verdict == VerdictPass && (fail || cnv) {
		return fmt.Errorf("%w: a pass verdict cannot carry a failed or unanswered check", ErrInvalid)
	}
	if len(n.Findings) > maxFindings {
		return fmt.Errorf("%w: too many findings", ErrInvalid)
	}
	seen := make(map[string]struct{}, len(n.Findings))
	for _, f := range n.Findings {
		if err := f.validate(); err != nil {
			return err
		}
		if _, dup := seen[f.Fingerprint]; dup {
			return fmt.Errorf("%w: duplicate finding fingerprint", ErrInvalid)
		}
		seen[f.Fingerprint] = struct{}{}
	}
	return nil
}

// newSalt draws the 128 random bits of DM-24 digest_salt.
func newSalt() []byte {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic("connection: no entropy: " + err.Error())
	}
	return b
}

// Digest domain tags (DM-24.I5, DM-25.I7). Each digest has its own tag, so two digests of different
// meaning never compare equal by construction.
const (
	findingsDigestTag = "adq-findings-digest/1"
	overrideDigestTag = "adq-override-digest/1"
)

// findingsDigest is DM-24.I5: SHA-256 over the adq-canon/1 encoding (ADR-0005 rule 11) of
// (tag, salt, the run's fingerprints sorted bytewise). The salt keeps an unkeyed reader from
// brute-forcing the enumerable inputs.
func findingsDigest(salt []byte, fingerprints []string) []byte {
	return saltedDigest(findingsDigestTag, salt, fingerprints)
}

// OverrideDigest is DM-25.I7: the same construction under adq-override-digest/1, over the
// fingerprints an override acknowledged, salted with its evidence run's digest_salt.
func OverrideDigest(salt []byte, fingerprints []string) []byte {
	return saltedDigest(overrideDigestTag, salt, fingerprints)
}

func saltedDigest(tag string, salt []byte, fingerprints []string) []byte {
	fps := slices.Clone(fingerprints)
	sort.Strings(fps)
	items := make([][]byte, len(fps))
	for i, fp := range fps {
		items[i] = []byte(fp)
	}
	var e canon.Encoder
	e.String(1, tag)
	e.Bytes(2, salt)
	e.List(3, items)
	enc, err := e.Result()
	if err != nil {
		// Unreachable: tags ascend and the tag constant is valid UTF-8. A fingerprint is hex text.
		panic("connection: digest encoding: " + err.Error())
	}
	sum := sha256.Sum256(enc)
	return sum[:]
}

// Errors of the verification and override paths. None carries a finding, an object identifier or a
// directory response (DM-24.I5).
var (
	// ErrVerificationNotFound: no such run for this connection.
	ErrVerificationNotFound = errors.New("connection: verification not found")
	// ErrActivationRefused is matched by *ActivationError: the connection did not become active.
	ErrActivationRefused = errors.New("connection: activation refused")
	// ErrOverrideRefused is matched by *OverrideError: no Tier-0 override was recorded.
	ErrOverrideRefused = errors.New("connection: tier0 override refused")
)

// Reasons the activation gate or the override refuses. They are stable machine codes.
const (
	ReasonNoVerification    = "no_verification"    // nothing has been verified yet
	ReasonStaleVerification = "stale_verification" // the newest run is older than 15 minutes
	ReasonCredentialChanged = "credential_changed" // the newest run verified another credential
	ReasonVerdictFailed     = "verdict_failed"     // a locate, clock, transport, auth, identity or topology check failed
	ReasonCouldNotVerify    = "could_not_verify"   // an unanswered question fails closed
	ReasonNotOverridable    = "not_overridable"    // more than over-privilege is wrong: never overridable
	ReasonOverPrivileged    = "over_privileged"    // over-privilege findings and no override covers them
	ReasonNewFinding        = "new_finding"        // an override exists but does not cover a current finding
	ReasonWrongState        = "wrong_state"        // the connection is not in a state this applies to
	ReasonNotLatestRun      = "not_latest_run"     // an override must name the connection's newest run
	ReasonNoFindings        = "no_findings"        // nothing to acknowledge
)

// ActivationError says why the activation gate (DM-10.I9) stayed shut.
type ActivationError struct{ Code string }

func (e *ActivationError) Error() string { return "connection: activation refused: " + e.Code }

// Is makes errors.Is(err, ErrActivationRefused) true.
func (e *ActivationError) Is(target error) bool { return target == ErrActivationRefused }

// OverrideError says why an override was not recorded.
type OverrideError struct{ Code string }

func (e *OverrideError) Error() string { return "connection: tier0 override refused: " + e.Code }

// Is makes errors.Is(err, ErrOverrideRefused) true.
func (e *OverrideError) Is(target error) bool { return target == ErrOverrideRefused }
