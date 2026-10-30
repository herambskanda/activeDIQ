package rbac

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

const runReports = authz.Permission("reports.run")

var rsNow = time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)

// termEvals is a test ScopeEvaluators: one evaluator per kind, each producing the term kind of the
// same name. override replaces what a kind's evaluator returns, to model a lying evaluator.
type termEvals struct {
	kinds    map[string]authz.TermKind
	override map[string]func(conn, root authz.ObjectID) (authz.ScopeTerm, error)
}

func stdEvals() termEvals {
	return termEvals{kinds: map[string]authz.TermKind{
		string(NamingContext): authz.TermNamingContext,
		string(OUSubtree):     authz.TermSubtree,
		string(OUOneLevel):    authz.TermOneLevel,
	}}
}

func (e termEvals) ScopeEvaluator(kind string) (authz.ScopeEvaluator, bool) {
	k, ok := e.kinds[kind]
	if !ok {
		return nil, false
	}
	return fakeEval{kind: kind, term: k, override: e.override[kind]}, true
}

type fakeEval struct {
	kind     string
	term     authz.TermKind
	override func(conn, root authz.ObjectID) (authz.ScopeTerm, error)
}

func (f fakeEval) RootKind() string { return f.kind }
func (f fakeEval) Term(c, r authz.ObjectID) (authz.ScopeTerm, error) {
	if f.override != nil {
		return f.override(c, r)
	}
	if c.IsZero() || r.IsZero() {
		return authz.ScopeTerm{}, authz.ErrInvalidObjectID
	}
	return authz.ScopeTerm{Kind: f.term, Connection: c, Root: r}, nil
}

type fakeOwner struct {
	active bool
	err    error
}

func (f fakeOwner) Active(context.Context, store.Tx, tenant.ID, string) (bool, error) {
	return f.active, f.err
}

// fakeConns maps object -> connection; an absent object is not found.
type fakeConns map[authz.ObjectID]authz.ObjectID

func (f fakeConns) ConnectionOf(_ context.Context, _ store.Tx, _ tenant.ID, o authz.ObjectID) (authz.ObjectID, bool, error) {
	c, ok := f[o]
	return c, ok, nil
}

func rsID(t testing.TB, s string) authz.ObjectID {
	t.Helper()
	id, err := authz.ParseObjectID(s)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func rsTenant(t testing.TB) tenant.ID {
	t.Helper()
	tn, err := tenant.Parse(tenantID)
	if err != nil {
		t.Fatal(err)
	}
	return tn
}

type rsOpt func(*rsEnv)

type rsEnv struct {
	src    fakeSrc
	opts   []Option
	evals  ScopeEvaluators
	owner  OwnerStatus
	conns  ObjectConnections
	chain  authority.Chain
	tokens *authz.Token
}

func withEvals(e ScopeEvaluators) rsOpt   { return func(x *rsEnv) { x.evals = e } }
func withOwner(o OwnerStatus) rsOpt       { return func(x *rsEnv) { x.owner = o } }
func withConns(c ObjectConnections) rsOpt { return func(x *rsEnv) { x.conns = c } }
func withSub(as ...Assignment) rsOpt      { return func(x *rsEnv) { x.src.sub = as } }
func withMembers(g authz.Groups) rsOpt {
	return func(x *rsEnv) { x.opts = append(x.opts, WithMembership(fakeMembers{g: g})) }
}
func withToken(tok authz.Token) rsOpt {
	return func(x *rsEnv) {
		x.tokens = &tok
		x.opts = append(x.opts, WithTokens(fakeTokens{tok: tok}))
		x.chain.Via = []authority.Principal{{ID: "tok-1", Kind: authority.APIToken}}
	}
}

func produce(t testing.TB, as []Assignment, opts ...rsOpt) (authz.ReadScope, error) {
	t.Helper()
	env := &rsEnv{src: fakeSrc{as: as}, evals: stdEvals(), owner: fakeOwner{active: true}, chain: human(acct)}
	for _, o := range opts {
		o(env)
	}
	a, err := New(env.src, env.opts...)
	if err != nil {
		t.Fatal(err)
	}
	a.now = func() time.Time { return rsNow }
	rs, err := NewReadScopes(a, env.evals, env.owner, env.conns)
	if err != nil {
		t.Fatal(err)
	}
	return rs.For(context.Background(), nil, rsTenant(t), env.chain, runReports)
}

func runAs(id string, perms []authz.Permission, roots ...Root) Assignment {
	return Assignment{ID: id, Subject: SubjectAccount, Permissions: perms, Roots: roots}
}

var (
	reportsP  = []authz.Permission{runReports}
	subtreeA  = Root{Kind: OUSubtree, Connection: conn, GUID: ouA}
	excludeB  = Root{Kind: OUSubtree, Connection: conn, GUID: ouB, Exclude: true}
	hasReason = func(s authz.ReadScope, r authz.ScopeReason) bool { return slices.Contains(s.Reasons(), r) }
	termOf3   = func(t testing.TB, k authz.TermKind, c, r string) authz.ScopeTerm {
		return authz.ScopeTerm{Kind: k, Connection: rsID(t, c), Root: rsID(t, r)}
	}
)

// AC1: an ou_subtree assignment with an exclude root gives one grant with that include and that exclude.
func TestReadScopesFor_OneGrantWithIncludeAndExclude(t *testing.T) {
	s, err := produce(t, []Assignment{runAs("a1", reportsP, subtreeA, excludeB)})
	if err != nil {
		t.Fatal(err)
	}
	g := s.Terms()
	if len(g) != 1 || s.Empty() {
		t.Fatalf("want one grant, got %+v", g)
	}
	if want := []authz.ScopeTerm{termOf3(t, authz.TermSubtree, conn, ouA)}; !slices.Equal(g[0].Include, want) {
		t.Fatalf("include = %+v", g[0].Include)
	}
	if want := []authz.ScopeTerm{termOf3(t, authz.TermSubtree, conn, ouB)}; !slices.Equal(g[0].Exclude, want) {
		t.Fatalf("exclude = %+v", g[0].Exclude)
	}
	if _, ok := s.Token(); ok {
		t.Fatal("a session has no token layer")
	}
	if len(s.Reasons()) != 0 {
		t.Fatalf("reasons = %v", s.Reasons())
	}
}

func TestReadScopesFor_AllThreeKindsAndMoreThanOneAssignment(t *testing.T) {
	s, err := produce(t, []Assignment{
		runAs("a1", reportsP, Root{Kind: NamingContext, Connection: conn, GUID: ncHead}),
		runAs("a2", reportsP, Root{Kind: OUOneLevel, Connection: conn2, GUID: ouB}),
		runAs("a3", []authz.Permission{"x.y"}, subtreeA), // does not hold the permission
	})
	if err != nil {
		t.Fatal(err)
	}
	g := s.Terms()
	if len(g) != 2 || g[0].Include[0].Kind != authz.TermNamingContext || g[1].Include[0].Kind != authz.TermOneLevel || g[1].Include[0].Connection != rsID(t, conn2) {
		t.Fatalf("grants = %+v", g)
	}
}

// Group assignments feed the same producer; membership that is incomplete grants nothing.
func TestReadScopesFor_GroupAssignments(t *testing.T) {
	own := runAs("own", []authz.Permission{"x.y"}, subtreeA)
	ga := groupAssign(reportsP, ouRoot)
	s, err := produce(t, []Assignment{own}, withSub(ga), withMembers(member))
	if err != nil || len(s.Terms()) != 1 {
		t.Fatalf("member: %+v %v", s.Terms(), err)
	}
	s, err = produce(t, []Assignment{own}, withSub(ga), withMembers(authz.Groups{Groups: member.Groups}))
	if err != nil || !s.Empty() {
		t.Fatalf("incomplete membership: %+v %v", s.Terms(), err)
	}
}

// AC2: a root kind with no evaluator contributes nothing and records the reason; an assignment whose
// exclude has no evaluator is dropped whole.
func TestReadScopesFor_UnsupportedKinds(t *testing.T) {
	s, err := produce(t, []Assignment{
		runAs("a1", reportsP, Root{Kind: EntraTenant, Connection: conn, GUID: conn}),
		runAs("a2", reportsP, subtreeA, Root{Kind: "group_members", Connection: conn, GUID: ouB, Exclude: true}),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !s.Empty() || len(s.Terms()) != 0 {
		t.Fatalf("both assignments must contribute nothing: %+v", s.Terms())
	}
	for _, k := range []string{"entra_tenant", "group_members"} {
		if !hasReason(s, authz.ScopeReason("scope_kind_unsupported:"+k)) {
			t.Errorf("missing reason for %s in %v", k, s.Reasons())
		}
	}
	// The unsupported include does not take a supported sibling down with it.
	s, err = produce(t, []Assignment{runAs("a1", reportsP, Root{Kind: EntraTenant, Connection: conn, GUID: conn}, subtreeA)})
	if err != nil || len(s.Terms()) != 1 || len(s.Terms()[0].Include) != 1 || !hasReason(s, "scope_kind_unsupported:entra_tenant") {
		t.Fatalf("sibling: %+v %v %v", s.Terms(), s.Reasons(), err)
	}
}

// AC4: Via grants and the tenant root contribute nothing; Tier-0 does not narrow reads.
func TestReadScopesFor_ViaTenantRootAndTier0(t *testing.T) {
	via := groupAssign(reportsP, ouRoot)
	viaMember := authz.Groups{Complete: true, Groups: []authz.Group{{Connection: conn, GUID: grpGUID, Via: &authz.Derivation{Correlation: &authz.Correlation{State: authz.CorrelationMatched, Takeover: authz.TakeoverAttested}}}}}
	tenantRoot := Root{Kind: TenantStore, Connection: tenantID, GUID: tenantID}
	s, err := produce(t, []Assignment{runAs("t", reportsP, tenantRoot), runAs("other", []authz.Permission{"x.y"}, subtreeA)}, withSub(via), withMembers(viaMember))
	if err != nil {
		t.Fatal(err)
	}
	if !s.Empty() || len(s.Terms()) != 0 {
		t.Fatalf("via and tenant root must contribute nothing: %+v", s.Terms())
	}
	if !hasReason(s, ReasonScopeViaNotApplied) {
		t.Errorf("reasons = %v", s.Reasons())
	}
	if hasReason(s, "scope_kind_unsupported:tenant") {
		t.Errorf("the tenant root is not an unsupported kind: %v", s.Reasons())
	}

	// A tenant root beside a directory root: only the directory root is a term.
	s, _ = produce(t, []Assignment{runAs("t", reportsP, tenantRoot, subtreeA)})
	if len(s.Terms()) != 1 || len(s.Terms()[0].Include) != 1 {
		t.Fatalf("tenant+ou: %+v", s.Terms())
	}

	// Tier-0: the scope has no Tier-0 term, and the oracle admits a Tier-0 target the scope covers.
	as := []Assignment{runAs("a1", reportsP, subtreeA)}
	s, _ = produce(t, as)
	if len(s.Terms()) != 1 {
		t.Fatalf("tier0: %+v", s.Terms())
	}
	tgt, ev, err := objectView(as, authority.TargetRef{Connection: conn, GUID: obj, Class: "user"}, authority.Facts{Exists: true, Tier0: true, Ancestors: []string{ouA, ncHead}, AncestorsComplete: true})
	if err != nil {
		t.Fatal(err)
	}
	p := &authz.Principal{ID: acct, Assignments: ev}
	if !(authz.Evaluator{}).AuthorizeRead(p, nil, runReports, tgt).Allowed {
		t.Fatal("read oracle must admit a Tier-0 target in scope")
	}
	if (authz.Evaluator{}).Authorize(p, nil, runReports, tgt).Allowed {
		t.Fatal("the write path must still refuse Tier-0")
	}
	// A tier0_scope root is not a directory read term.
	s, _ = produce(t, []Assignment{runAs("a1", reportsP, Root{Kind: Tier0Scope, Connection: conn, GUID: conn})})
	if !s.Empty() || !hasReason(s, "scope_kind_unsupported:tier0_scope") {
		t.Fatalf("tier0_scope: %v %v", s.Empty(), s.Reasons())
	}
}

// AC5: a token narrows (separate layer); a disabled owner is ErrOwnerDead.
func TestReadScopesFor_TokenLayer(t *testing.T) {
	ouAid, ouBid := rsID(t, ouA), rsID(t, ouB)
	conns := fakeConns{ouAid: rsID(t, conn), ouBid: rsID(t, conn)}
	tok := func(sc *authz.Scope) authz.Token {
		return authz.Token{Permissions: reportsP, ExpiresAt: rsNow.Add(time.Hour), Scope: sc}
	}
	as := []Assignment{runAs("a1", reportsP, Root{Kind: NamingContext, Connection: conn, GUID: ncHead})}

	t.Run("narrowing roots become subtree terms in the token layer", func(t *testing.T) {
		s, err := produce(t, as, withToken(tok(&authz.Scope{
			Include: []authz.ScopeRoot{{ID: ouAid}}, Exclude: []authz.ScopeRoot{{ID: ouBid}}})), withConns(conns))
		if err != nil {
			t.Fatal(err)
		}
		l, ok := s.Token()
		if !ok || s.Empty() {
			t.Fatalf("token layer %v empty=%v", ok, s.Empty())
		}
		if !slices.Equal(l.Include, []authz.ScopeTerm{termOf3(t, authz.TermSubtree, conn, ouA)}) ||
			!slices.Equal(l.Exclude, []authz.ScopeTerm{termOf3(t, authz.TermSubtree, conn, ouB)}) {
			t.Fatalf("layer = %+v", l)
		}
		if len(s.Terms()) != 1 || len(s.Terms()[0].Include) != 1 || s.Terms()[0].Include[0].Root != rsID(t, ncHead) {
			t.Fatalf("the grants must stay the account's: %+v", s.Terms())
		}
	})
	t.Run("a one-level include root stays one level", func(t *testing.T) {
		s, _ := produce(t, as, withToken(tok(&authz.Scope{Include: []authz.ScopeRoot{{ID: ouAid, OneLevel: true}}})), withConns(conns))
		if l, _ := s.Token(); len(l.Include) != 1 || l.Include[0].Kind != authz.TermOneLevel {
			t.Fatalf("layer = %+v", l)
		}
	})
	t.Run("a nil scope adds no layer", func(t *testing.T) {
		s, err := produce(t, as, withToken(tok(nil)))
		if _, ok := s.Token(); ok || err != nil || s.Empty() {
			t.Fatalf("ok=%v empty=%v err=%v", ok, s.Empty(), err)
		}
	})
	t.Run("a non-nil empty scope grants nothing", func(t *testing.T) {
		s, err := produce(t, as, withToken(tok(&authz.Scope{})))
		if _, ok := s.Token(); !ok || !s.Empty() || err != nil {
			t.Fatalf("ok=%v empty=%v err=%v", ok, s.Empty(), err)
		}
	})
	t.Run("an unresolvable or zero root grants nothing", func(t *testing.T) {
		for name, sc := range map[string]*authz.Scope{
			"unknown object":  {Include: []authz.ScopeRoot{{ID: rsID(t, obj)}}},
			"zero include":    {Include: []authz.ScopeRoot{{ID: ouAid}, {}}},
			"unknown exclude": {Include: []authz.ScopeRoot{{ID: ouAid}}, Exclude: []authz.ScopeRoot{{ID: rsID(t, obj)}}},
			"zero exclude":    {Include: []authz.ScopeRoot{{ID: ouAid}}, Exclude: []authz.ScopeRoot{{}}},
		} {
			s, err := produce(t, as, withToken(tok(sc)), withConns(conns))
			if err != nil || !s.Empty() || !hasReason(s, ReasonScopeTokenUnresolved) {
				t.Errorf("%s: empty=%v reasons=%v err=%v", name, s.Empty(), s.Reasons(), err)
			}
		}
		s, _ := produce(t, as, withToken(tok(&authz.Scope{Include: []authz.ScopeRoot{{ID: ouAid}}}))) // no inventory port
		if !s.Empty() {
			t.Error("without a connection resolver a scoped token must read nothing")
		}
	})
	t.Run("expired, no expiry and unlisted permission are refused", func(t *testing.T) {
		for name, tk := range map[string]authz.Token{
			"expired":   {Permissions: reportsP, ExpiresAt: rsNow.Add(-time.Second)},
			"no expiry": {Permissions: reportsP},
			"unlisted":  {Permissions: []authz.Permission{"x.y"}, ExpiresAt: rsNow.Add(time.Hour)},
		} {
			if _, err := produce(t, as, withToken(tk)); !errors.Is(err, authz.ErrTokenRefused) {
				t.Errorf("%s: %v", name, err)
			}
		}
	})
	t.Run("a token chain without a token source is refused", func(t *testing.T) {
		env := func(x *rsEnv) { x.chain.Via = []authority.Principal{{ID: "tok-1", Kind: authority.APIToken}} }
		if _, err := produce(t, as, env); !errors.Is(err, authz.ErrTokenRefused) {
			t.Fatalf("got %v", err)
		}
	})
}

func TestReadScopesFor_DeadOwner(t *testing.T) {
	as := []Assignment{runAs("a1", reportsP, subtreeA)}
	if _, err := produce(t, as, withOwner(fakeOwner{active: false})); !errors.Is(err, authz.ErrOwnerDead) {
		t.Fatalf("disabled: %v", err)
	}
	if _, err := produce(t, nil); !errors.Is(err, authz.ErrOwnerDead) {
		t.Fatalf("lost every assignment: %v", err)
	}
	boom := errors.New("db down")
	if _, err := produce(t, as, withOwner(fakeOwner{err: boom})); !errors.Is(err, boom) || errors.Is(err, authz.ErrOwnerDead) {
		t.Fatalf("a failed status read is an error, not a dead owner: %v", err)
	}
	// Holding assignments but none with the permission is an empty scope, not a dead owner.
	s, err := produce(t, []Assignment{runAs("a1", []authz.Permission{"x.y"}, subtreeA)})
	if err != nil || !s.Empty() {
		t.Fatalf("empty=%v err=%v", s.Empty(), err)
	}
}

func TestReadScopesFor_UnsupportedChains(t *testing.T) {
	as := []Assignment{runAs("a1", reportsP, subtreeA)}
	for name, c := range map[string]authority.Chain{
		"no requester": {},
		"not human":    {Requester: authority.Principal{ID: "svc", Kind: authority.System}},
		"automation":   {Requester: authority.Principal{ID: acct, Kind: authority.Human}, Via: []authority.Principal{{ID: policy, Kind: authority.Automation}}},
		"two tokens": {Requester: authority.Principal{ID: acct, Kind: authority.Human}, Via: []authority.Principal{
			{ID: "t1", Kind: authority.APIToken}, {ID: "t2", Kind: authority.APIToken}}},
	} {
		if _, err := produce(t, as, func(x *rsEnv) { x.chain = c }); !errors.Is(err, ErrUnsupportedChain) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestNewReadScopesNeedsItsParts(t *testing.T) {
	a := az(t)
	if _, err := NewReadScopes(nil, stdEvals(), fakeOwner{}, nil); err == nil {
		t.Error("nil authorizer")
	}
	if _, err := NewReadScopes(a, nil, fakeOwner{}, nil); err == nil {
		t.Error("nil evaluators")
	}
	if _, err := NewReadScopes(a, stdEvals(), nil, nil); err == nil {
		t.Error("nil owner status")
	}
}

// Security-architect (T-0880): an evaluator is module code. A term that is valid but names another
// connection or root, or a broader kind, must drop the grant and say why.
func TestReadScopesFor_LyingEvaluator(t *testing.T) {
	other := rsID(t, ouB)
	cases := map[string]func(c, r authz.ObjectID) (authz.ScopeTerm, error){
		"other connection": func(c, r authz.ObjectID) (authz.ScopeTerm, error) {
			return authz.ScopeTerm{Kind: authz.TermSubtree, Connection: rsID(t, conn2), Root: r}, nil
		},
		"other root": func(c, r authz.ObjectID) (authz.ScopeTerm, error) {
			return authz.ScopeTerm{Kind: authz.TermSubtree, Connection: c, Root: other}, nil
		},
		"broader kind": func(c, r authz.ObjectID) (authz.ScopeTerm, error) {
			return authz.ScopeTerm{Kind: authz.TermNamingContext, Connection: c, Root: r}, nil
		},
		"unknown kind": func(c, r authz.ObjectID) (authz.ScopeTerm, error) {
			return authz.ScopeTerm{Kind: 0, Connection: c, Root: r}, nil
		},
		"undefined kind": func(c, r authz.ObjectID) (authz.ScopeTerm, error) {
			return authz.ScopeTerm{Kind: 99, Connection: c, Root: r}, nil
		},
		"evaluator error": func(c, r authz.ObjectID) (authz.ScopeTerm, error) {
			return authz.ScopeTerm{}, errors.New("boom")
		},
	}
	for name, f := range cases {
		for where, roots := range map[string][]Root{"include": {subtreeA}, "exclude": {subtreeA, {Kind: OUSubtree, Connection: conn, GUID: ouB, Exclude: true}}} {
			ev := stdEvals()
			ev.override = map[string]func(c, r authz.ObjectID) (authz.ScopeTerm, error){string(OUSubtree): f}
			s, err := produce(t, []Assignment{runAs("a1", reportsP, roots...)}, withEvals(ev))
			if err != nil || !s.Empty() || len(s.Terms()) != 0 || !hasReason(s, ReasonScopeTermInvalid) {
				t.Errorf("%s/%s: empty=%v grants=%+v reasons=%v err=%v", name, where, s.Empty(), s.Terms(), s.Reasons(), err)
			}
		}
	}
	// One lying assignment does not take an honest one down.
	ev := stdEvals()
	ev.override = map[string]func(c, r authz.ObjectID) (authz.ScopeTerm, error){string(OUOneLevel): cases["broader kind"]}
	s, _ := produce(t, []Assignment{
		runAs("liar", reportsP, Root{Kind: OUOneLevel, Connection: conn, GUID: ouB}),
		runAs("honest", reportsP, subtreeA),
	}, withEvals(ev))
	if len(s.Terms()) != 1 || s.Terms()[0].Include[0].Root != rsID(t, ouA) {
		t.Fatalf("grants = %+v", s.Terms())
	}
}

// A malformed stored GUID cannot be bound: an include is dropped with its grant, an exclude drops the grant.
func TestReadScopesFor_MalformedRootsFailClosed(t *testing.T) {
	bad := Root{Kind: OUSubtree, Connection: conn, GUID: "not-a-guid", Exclude: true}
	s, _ := produce(t, []Assignment{runAs("a1", reportsP, subtreeA, bad)})
	if !s.Empty() || !hasReason(s, ReasonScopeTermInvalid) {
		t.Fatalf("bad exclude: %+v %v", s.Terms(), s.Reasons())
	}
	zero := Root{Kind: OUSubtree, Connection: conn, GUID: "00000000-0000-0000-0000-000000000000"}
	s, _ = produce(t, []Assignment{runAs("a1", reportsP, zero)})
	if !s.Empty() {
		t.Fatalf("zero root: %+v", s.Terms())
	}
}

func TestReadScopesFor_ReasonsAreSortedAndUnique(t *testing.T) {
	s, _ := produce(t, []Assignment{
		runAs("a1", reportsP, Root{Kind: EntraTenant, Connection: conn, GUID: conn}),
		runAs("a2", reportsP, Root{Kind: EntraTenant, Connection: conn2, GUID: conn2}),
		runAs("a3", reportsP, Root{Kind: Tier0Scope, Connection: conn, GUID: conn}),
	})
	want := []authz.ScopeReason{"scope_kind_unsupported:entra_tenant", "scope_kind_unsupported:tier0_scope"}
	if !slices.Equal(s.Reasons(), want) {
		t.Fatalf("reasons = %v", s.Reasons())
	}
	if s.Summary() == "" {
		t.Fatal("summary must say something for scope_applied")
	}
}
