package write

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/skenzeriq/activediq/internal/connector/ad"
	"github.com/skenzeriq/activediq/internal/connector/tier0"
	"github.com/skenzeriq/activediq/internal/connector/write/ops"
	"github.com/skenzeriq/activediq/internal/directory/accountkind"
	"github.com/skenzeriq/activediq/internal/directory/attr/flags"
	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/attr/unicodepwd"
	"github.com/skenzeriq/activediq/internal/directory/dn"
	"github.com/skenzeriq/activediq/internal/platform/operation/digest"
	"github.com/skenzeriq/activediq/internal/platform/secret"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// The four account kinds of connector-contract §8.10.3 (T-1583): reset password, unlock, enable and
// disable. Each is a WriteOp row; the Tier-0 guard, the write gate and the property guard run before
// any of this code (§8.1 steps 1 to 7), and the LDAP requests are built in write/ops.

// AccountSession is what the account kinds need from a directory session; *ad.Session implements it.
type AccountSession interface {
	DCIdentity(ctx context.Context) (ad.DCIdentity, error)
	ReadAccount(ctx context.Context, ref dn.ObjectRef) (ad.AccountState, error)
	ModifyAccount(ctx context.Context, ref dn.ObjectRef, check ad.AccountCheck, send ad.AccountSender, needSecure bool) error
}

// AccountProvider is implemented by a Provider that can write accounts. The AD provider built over a
// session is one; the Entra provider is not (those kinds answer CAPABILITY_UNSUPPORTED).
type AccountProvider interface {
	AccountSession() AccountSession
}

// AccountSession returns the session the provider's reads and DC binding run on.
func (p *ADProvider) AccountSession() AccountSession {
	if p == nil || p.Accounts == nil {
		return nil
	}
	return p.Accounts
}

func init() {
	for _, sp := range accountkind.Specs() {
		operations[sp.Kind] = accountOp(sp)
	}
}

func accountOp(sp accountkind.Spec) WriteOp {
	return WriteOp{
		WantsSecret: sp.Key == accountkind.KeyResetPassword,
		Arm: func(c *connectorv1.WriteChange) bool {
			_, err := accountkind.AttrsOf(sp.Key, c, sp.Key == accountkind.KeyResetPassword)
			return err == nil
		},
		Touched: func(target guid.GUID, c *connectorv1.WriteChange) ([]guid.GUID, error) {
			return []guid.GUID{target}, nil
		},
		PropertyWrite: func(c *connectorv1.WriteChange) (tier0.PropertyWrite, error) {
			keys := map[string][]string{
				accountkind.KeyResetPassword: {"unicodePwd", "pwdLastSet"},
				accountkind.KeyUnlock:        {"lockoutTime"},
				accountkind.KeyEnable:        {"userAccountControl"},
				accountkind.KeyDisable:       {"userAccountControl"},
			}[sp.Key]
			// The class is read live later; the guard's user declaration covers computers' keys too.
			return tier0.PropertyWrite{Plane: tier0.PlaneAD, Kind: tier0.WriteUser, Op: tier0.OpUpdate, Keys: keys}, nil
		},
		Digest: func(req *connectorv1.ApplyRequest) ([]byte, error) { return accountDigest(sp, req) },
		Plan: func(ctx context.Context, a Authorised, req *connectorv1.PlanRequest) (*connectorv1.PlanResponse, error) {
			return planAccount(ctx, sp, a, req)
		},
		Apply: func(ctx context.Context, a Authorised, req *connectorv1.ApplyRequest) (*connectorv1.ApplyResponse, error) {
			return applyAccount(ctx, sp, a, req)
		},
	}
}

// uuidText is the canonical lower-case text of a wire Guid (RFC 4122 order), the form the server
// digests.
func uuidText(g *connectorv1.Guid) (string, error) {
	b := g.GetValue()
	if len(b) != 16 {
		return "", errBadGUID
	}
	h := hex.EncodeToString(b)
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:], nil
}

// accountDigest recomputes the plan digest from the typed request with the shared function. The class
// label is the server's (user or computer); the live class is checked separately, so each class the
// kind allows is tried and the one that matches the request is returned.
func accountDigest(sp accountkind.Spec, req *connectorv1.ApplyRequest) ([]byte, error) {
	obj, err := uuidText(req.GetTarget().GetObject())
	if err != nil {
		return nil, err
	}
	nc, err := uuidText(req.GetTarget().GetNcGuid())
	if err != nil {
		return nil, err
	}
	attrs, err := accountkind.AttrsOf(sp.Key, req.GetChange(), req.GetSecretInput() != nil)
	if err != nil {
		return nil, err
	}
	var first []byte
	for _, cls := range sp.Classes {
		d := digest.Compute(sp.Key, accountkind.Target(req.GetConnection().GetConnectionId(), obj, cls, nc), attrs)
		if first == nil {
			first = d[:]
		}
		if bytes.Equal(d[:], req.GetPlanDigest()) {
			return d[:], nil
		}
	}
	return first, nil
}

// session returns the account session behind the token, after the checks every body repeats: the token
// is the guard's and the session is bound to the DC the guard evaluated on.
func session(ctx context.Context, a Authorised, target guid.GUID) (AccountSession, ad.DCIdentity, error) {
	if !a.Valid() || a.p.prov == nil {
		return nil, ad.DCIdentity{}, unsupported()
	}
	ap, ok := a.p.prov.(AccountProvider)
	if !ok || ap.AccountSession() == nil {
		return nil, ad.DCIdentity{}, unsupported()
	}
	if ev := a.Evaluated(); len(ev) == 0 || ev[0] != target || a.DC() == (guid.GUID{}) {
		return nil, ad.DCIdentity{}, errors.New("write: account write targets an object the guard did not evaluate")
	}
	s := ap.AccountSession()
	id, err := s.DCIdentity(ctx)
	if err != nil {
		return nil, ad.DCIdentity{}, adRefusal(err)
	}
	if id.DSAGUID != a.DC() {
		return nil, ad.DCIdentity{}, pinRefusal("7")
	}
	return s, id, nil
}

// adRefusal maps a session error to a contract error with fixed text.
func adRefusal(err error) error {
	var r *Refusal
	if errors.As(err, &r) {
		return err
	}
	switch ad.CodeOf(err) {
	case ad.CodeObjectNotFound:
		return newRefusal(connectorv1.ErrorCode_ERROR_CODE_OBJECT_NOT_FOUND, connectorv1.RetryAdvice_RETRY_ADVICE_NEVER, "7", "object not found")
	case ad.CodeInsufficientRights:
		return newRefusal(connectorv1.ErrorCode_ERROR_CODE_INSUFFICIENT_RIGHTS, connectorv1.RetryAdvice_RETRY_ADVICE_AFTER_OPERATOR_ACTION, "8", "insufficient rights")
	case ad.CodeInsecure:
		return newRefusal(connectorv1.ErrorCode_ERROR_CODE_TRANSPORT_SECURITY, connectorv1.RetryAdvice_RETRY_ADVICE_NEVER, "8", "connection is not encrypted and verified")
	case ad.CodeStaleValue:
		return newRefusal(connectorv1.ErrorCode_ERROR_CODE_TARGET_CHANGED, connectorv1.RetryAdvice_RETRY_ADVICE_AFTER_REPLAN, "8", "target changed since plan")
	case ad.CodePasswordPolicy:
		return invalid("8", "PasswordPolicy", "secret_input")
	case ad.CodeUnreachable, ad.CodeCanceled:
		return newRefusal(connectorv1.ErrorCode_ERROR_CODE_UNREACHABLE_DC, connectorv1.RetryAdvice_RETRY_ADVICE_AFTER_REPLAN, "8", "domain controller unreachable")
	}
	return newRefusal(connectorv1.ErrorCode_ERROR_CODE_PROVIDER_FAILURE, connectorv1.RetryAdvice_RETRY_ADVICE_NEVER, "8", "directory call failed")
}

// classOf reads the live class: computer first (a computer is also a user), then user. A managed
// service account, which is a computer subclass, and everything else is not in the slice.
func classOf(st ad.AccountState) string {
	var user, computer, other bool
	for _, c := range st.Classes {
		switch strings.ToLower(c) {
		case "computer":
			computer = true
		case "user":
			user = true
		case "msds-groupmanagedserviceaccount", "msds-managedserviceaccount", "msds-delegatedmanagedserviceaccount":
			other = true
		}
	}
	switch {
	case other:
		return ""
	case computer:
		return accountkind.ClassComputer
	case user:
		return accountkind.ClassUser
	}
	return ""
}

func classCheck(sp accountkind.Spec, st ad.AccountState) error {
	if !sp.AllowsClass(classOf(st)) {
		return invalid("5", "ClassNotAllowed", "target")
	}
	if !st.HasUAC && sp.Key != accountkind.KeyUnlock {
		return invalid("5", "UnreadableAttribute", "target")
	}
	return nil
}

var errAlready = errors.New("write: already in the requested state")

func disabled(st ad.AccountState) bool { return uint32(st.UAC)&uint32(flags.UACAccountDisable) != 0 }

// satisfied reports whether the account is already in the state the kind asks for. A reset is never.
func satisfied(sp accountkind.Spec, st ad.AccountState) bool {
	switch sp.Key {
	case accountkind.KeyUnlock:
		return st.LockoutTime == 0
	case accountkind.KeyEnable:
		return !disabled(st)
	case accountkind.KeyDisable:
		return disabled(st)
	}
	return false
}

// stateDigest is the precondition: the attributes the kind reads or changes, hashed (contract
// §8.10.3). Enable and disable also carry their compare in the Modify itself.
func stateDigest(sp accountkind.Spec, st ad.AccountState) []byte {
	h := sha256.New()
	put := func(s string) {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(s)))
		h.Write(n[:])
		h.Write([]byte(s))
	}
	put("adq-account-state/1")
	put(sp.Key)
	g := st.GUID.String()
	put(g)
	i := func(n int64) { put(strconv.FormatInt(n, 10)) }
	switch sp.Key {
	case accountkind.KeyResetPassword:
		put(strconv.FormatUint(st.USN, 10))
		i(st.PwdLastSet)
		i(int64(st.UAC))
		i(st.LockoutTime)
		put(hex.EncodeToString(st.SID))
	case accountkind.KeyUnlock:
		put(strconv.FormatUint(st.USN, 10))
		i(st.LockoutTime)
	default:
		i(int64(st.UAC))
	}
	return h.Sum(nil)
}

func attrEntry(st ad.AccountState, sp accountkind.Spec) *connectorv1.DirectoryEntry {
	e := &connectorv1.DirectoryEntry{ObjectGuid: toWire(st.GUID)}
	add := func(name string, v *connectorv1.AttributeValue) {
		e.Attributes = append(e.Attributes, &connectorv1.Attribute{Name: name, Values: []*connectorv1.AttributeValue{v}, Complete: true})
	}
	switch sp.Key {
	case accountkind.KeyResetPassword:
		add("pwdLastSet", &connectorv1.AttributeValue{Value: &connectorv1.AttributeValue_Int64Value{Int64Value: st.PwdLastSet}})
	case accountkind.KeyUnlock:
		add("lockoutTime", &connectorv1.AttributeValue{Value: &connectorv1.AttributeValue_Int64Value{Int64Value: st.LockoutTime}})
	default:
		add("userAccountControl", &connectorv1.AttributeValue{Value: &connectorv1.AttributeValue_Int32Value{Int32Value: st.UAC}})
	}
	return e
}

func observation(id ad.DCIdentity) *connectorv1.Observation {
	return &connectorv1.Observation{
		Dc:         &connectorv1.DcIdentity{DsaGuid: toWire(id.DSAGUID), InvocationId: toWire(id.InvocationID), DnsHostname: id.DNSHostName, Site: id.Site},
		ReceivedAt: timestamppb.New(time.Now()),
	}
}

func planAccount(ctx context.Context, sp accountkind.Spec, a Authorised, req *connectorv1.PlanRequest) (*connectorv1.PlanResponse, error) {
	target, err := fromWire(req.GetTarget().GetObject())
	if err != nil {
		return nil, invalid("1", "TargetRequired", "target.object")
	}
	s, id, err := session(ctx, a, target)
	if err != nil {
		return nil, err
	}
	st, err := s.ReadAccount(ctx, dn.GUIDRef(target))
	if err != nil {
		return nil, adRefusal(err)
	}
	if st.GUID != target {
		return nil, invalid("5", "TargetRequired", "target.object")
	}
	if err := classCheck(sp, st); err != nil {
		return nil, err
	}
	usn := st.USN
	return &connectorv1.PlanResponse{
		Observed:     observation(id),
		Precondition: &connectorv1.TargetPrecondition{UsnChanged: &usn, StateDigest: stateDigest(sp, st)},
		NoOp:         satisfied(sp, st),
		Before:       attrEntry(st, sp),
	}, nil
}

func applyAccount(ctx context.Context, sp accountkind.Spec, a Authorised, req *connectorv1.ApplyRequest) (*connectorv1.ApplyResponse, error) {
	target, err := fromWire(req.GetTarget().GetObject())
	if err != nil {
		return nil, invalid("1", "TargetRequired", "target.object")
	}
	s, id, err := session(ctx, a, target)
	if err != nil {
		return nil, err
	}
	var seen ad.AccountState
	check := func(st ad.AccountState) error {
		seen = st
		if st.GUID != target {
			return invalid("5", "TargetRequired", "target.object")
		}
		if err := classCheck(sp, st); err != nil {
			return err
		}
		if satisfied(sp, st) {
			return errAlready
		}
		if !bytes.Equal(stateDigest(sp, st), req.GetPrecondition().GetStateDigest()) ||
			(req.GetPrecondition().UsnChanged != nil && req.GetPrecondition().GetUsnChanged() != st.USN) {
			return newRefusal(connectorv1.ErrorCode_ERROR_CODE_TARGET_CHANGED, connectorv1.RetryAdvice_RETRY_ADVICE_AFTER_REPLAN, "8", "target changed since plan")
		}
		return nil
	}
	var send ad.AccountSender
	secure := false
	switch sp.Key {
	case accountkind.KeyUnlock:
		send = ops.ClearLockout()
	case accountkind.KeyEnable, accountkind.KeyDisable:
		// The delete-old value is the one the check is about to read; read it inside the lock via a
		// late-bound sender so a bit changed by a second writer between Plan and now fails the delete.
		send = func(m ad.Modifier, d string, sc unicodepwd.SecureConn) error {
			next := seen.UAC
			if sp.Key == accountkind.KeyEnable {
				next &^= int32(flags.UACAccountDisable)
			} else {
				next |= int32(flags.UACAccountDisable)
			}
			return ops.ReplaceUAC(seen.UAC, next)(m, d, sc)
		}
	case accountkind.KeyResetPassword:
		secure = true
		var pw secret.Secret
		if m := req.GetSecretInput().GetMaterial(); len(m) > 0 {
			pw = secret.FromBytes(m)
			defer pw.Destroy()
		}
		send = ops.ResetPassword(pw, req.GetChange().GetUserPasswordReset().GetMustChangeAtNextLogon())
	}
	err = s.ModifyAccount(ctx, dn.GUIDRef(target), check, send, secure)
	switch {
	case errors.Is(err, errAlready):
		return &connectorv1.ApplyResponse{Outcome: connectorv1.ApplyOutcome_APPLY_OUTCOME_ALREADY_APPLIED,
			Written: observation(id), ReadBack: attrEntry(seen, sp)}, nil
	case err != nil:
		return nil, adRefusal(err)
	}
	after, err := s.ReadAccount(ctx, dn.GUIDRef(target)) // read-after-write on the same bound DC
	if err != nil {
		return nil, adRefusal(err)
	}
	usn := after.USN
	if sp.Key != accountkind.KeyResetPassword && !satisfied(sp, after) {
		return nil, newRefusal(connectorv1.ErrorCode_ERROR_CODE_PROVIDER_FAILURE, connectorv1.RetryAdvice_RETRY_ADVICE_NEVER, "8", "write not visible on the bound domain controller")
	}
	return &connectorv1.ApplyResponse{Outcome: connectorv1.ApplyOutcome_APPLY_OUTCOME_APPLIED,
		Written: observation(id), UsnChangedAfter: &usn, ReadBack: attrEntry(after, sp)}, nil
}
