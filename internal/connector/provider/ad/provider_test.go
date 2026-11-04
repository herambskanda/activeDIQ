package ad

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"

	adconn "github.com/skenzeriq/activediq/internal/connector/ad"
	"github.com/skenzeriq/activediq/internal/connector/provider"
	"github.com/skenzeriq/activediq/internal/connector/tier0"
	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/attr/sid"
	"github.com/skenzeriq/activediq/internal/directory/dn"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

func mk(n byte) guid.GUID {
	b := make([]byte, 16)
	b[0], b[15] = n, 1
	g, err := guid.FromBytes(b)
	if err != nil {
		panic(err)
	}
	return g
}

func adIdentity() *connectorv1.DirectoryIdentity {
	return &connectorv1.DirectoryIdentity{Identity: &connectorv1.DirectoryIdentity_AdForest{AdForest: &connectorv1.AdForestIdentity{
		ForestRootNcGuid: provider.GUIDToWire(mk(200))}}}
}

// CC-WRITE-20 g: a GPO whose cn is not a GUID is tier0; ordinary objects are not touched by the rule.
func TestGPOCNMustBeAGUID(t *testing.T) {
	gpo := func(cn string) *adconn.Entry {
		return adconn.NewEntry("CN="+cn+",CN=Policies,CN=System,DC=lab,DC=test", map[string][][]byte{
			"objectClass": {[]byte("top"), []byte("container"), []byte("groupPolicyContainer")}, "cn": {[]byte(cn)}})
	}
	for cn, want := range map[string]bool{
		"{31B2F340-016D-11D2-945F-00C04FB984F9}": false, "31b2f340-016d-11d2-945f-00c04fb984f9": false,
		"Default Domain Policy": true, "{not-a-guid}": true, "": true,
	} {
		if got := gpoCNInvalid(gpo(cn)); got != want {
			t.Errorf("cn %q: %v want %v", cn, got, want)
		}
	}
	user := adconn.NewEntry("CN=x,DC=lab,DC=test", map[string][][]byte{"objectClass": {[]byte("user")}, "cn": {[]byte("x")}})
	if gpoCNInvalid(user) {
		t.Error("a user is not subject to the GPO cn rule")
	}
}

// designatedDir is a minimal ADDirectory: Get answers per object GUID. The base classifier is
// substituted, so Naming and Find are never reached.
type designatedDir struct {
	tier0.ADDirectory
	objs map[guid.GUID]*adconn.Entry
	errs map[guid.GUID]error
}

func (d *designatedDir) Get(_ context.Context, ref dn.ObjectRef, _ []string) (*adconn.Entry, error) {
	id, ok := ref.GUID()
	if !ok {
		return nil, errors.New("test: GUID refs only")
	}
	if e := d.errs[id]; e != nil {
		return nil, e
	}
	if o := d.objs[id]; o != nil {
		return o, nil
	}
	return nil, &adconn.Error{Code: adconn.CodeObjectNotFound}
}

func sidBytes(t *testing.T, s string) []byte {
	t.Helper()
	v, err := sid.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return v.Bytes()
}

func adRig(t *testing.T) (*ADProvider, *designatedDir, guid.GUID, guid.GUID) {
	t.Helper()
	user, grp := mk(70), mk(71)
	d := &designatedDir{objs: map[guid.GUID]*adconn.Entry{
		user: adconn.NewEntry("CN=u,DC=lab", map[string][][]byte{"objectClass": {[]byte("user")}, "cn": {[]byte("u")},
			"tokenGroups": {sidBytes(t, "S-1-5-21-1-2-3-1100"), sidBytes(t, "S-1-5-21-1-2-3-513")}}),
		grp: adconn.NewEntry("CN=g,DC=lab", map[string][][]byte{"objectSid": {sidBytes(t, "S-1-5-21-1-2-3-1100")}}),
	}, errs: map[guid.GUID]error{}}
	p := &ADProvider{Dir: d, Pins: &memPins{}}
	p.classify = func(_ context.Context, id guid.GUID, _ tier0.ADInput) (tier0.ADResult, error) {
		return tier0.ADResult{GUID: id}, nil
	}
	return p, d, user, grp
}

// Review finding 3: the designated path of ADProvider.Classify, and the Unknown and GUID-mismatch
// refusals, each fail closed.
func TestADProviderDesignated(t *testing.T) {
	ctx := context.Background()
	p, d, user, grp := adRig(t)

	if v, err := p.Classify(ctx, user, nil); err != nil || v.Tier0 {
		t.Fatalf("no designation: %+v %v", v, err)
	}
	v, err := p.Classify(ctx, user, []guid.GUID{grp})
	if err != nil || !v.Tier0 || len(v.Bases) != 1 || v.Bases[0] != tier0.Designated {
		t.Fatalf("member of a designated group: %+v %v", v, err)
	}
	// A designated group that is not found designates nothing; the object is not tier0 through it.
	if v, err := p.Classify(ctx, user, []guid.GUID{mk(72)}); err != nil || v.Tier0 {
		t.Fatalf("missing designated group: %+v %v", v, err)
	}
	// Not a member.
	d.objs[grp] = adconn.NewEntry("CN=g,DC=lab", map[string][][]byte{"objectSid": {sidBytes(t, "S-1-5-21-1-2-3-1200")}})
	if v, err := p.Classify(ctx, user, []guid.GUID{grp}); err != nil || v.Tier0 {
		t.Fatalf("non-member: %+v %v", v, err)
	}
	// Any other read error is refused (Tier0 true with an error).
	d.errs[grp] = &adconn.Error{Code: adconn.CodeProtocol}
	if v, err := p.Classify(ctx, user, []guid.GUID{grp}); err == nil || !v.Tier0 {
		t.Fatalf("read error must fail closed: %+v %v", v, err)
	}
	delete(d.errs, grp)
	d.errs[user] = &adconn.Error{Code: adconn.CodeProtocol}
	if v, err := p.Classify(ctx, user, []guid.GUID{grp}); err == nil || !v.Tier0 {
		t.Fatalf("token read error must fail closed: %+v %v", v, err)
	}
}

func TestADProviderClassifierAnswersFailClosed(t *testing.T) {
	ctx := context.Background()
	p, _, user, _ := adRig(t)
	p.classify = func(context.Context, guid.GUID, tier0.ADInput) (tier0.ADResult, error) {
		return tier0.ADResult{Unknown: true, Tier0: true, GUID: user}, nil
	}
	if v, err := p.Classify(ctx, user, nil); err == nil || !v.Tier0 {
		t.Fatalf("Unknown result: %+v %v", v, err)
	}
	p.classify = func(context.Context, guid.GUID, tier0.ADInput) (tier0.ADResult, error) {
		return tier0.ADResult{GUID: mk(99)}, nil
	}
	if v, err := p.Classify(ctx, user, nil); err == nil || !v.Tier0 {
		t.Fatalf("GUID mismatch: %+v %v", v, err)
	}
	p.classify = func(context.Context, guid.GUID, tier0.ADInput) (tier0.ADResult, error) {
		return tier0.ADResult{}, errors.New("dc down")
	}
	if v, err := p.Classify(ctx, user, nil); err == nil || !v.Tier0 {
		t.Fatalf("classifier error: %+v %v", v, err)
	}
}

// memPins is an in-memory PinStore with failure injection.
type memPins struct {
	mu             sync.Mutex
	pins           []guid.GUID
	getErr, putErr error
	reads          int
}

func (m *memPins) PinnedC13(context.Context) ([]guid.GUID, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.reads++
	return append([]guid.GUID(nil), m.pins...), m.getErr
}

func (m *memPins) PinC13(_ context.Context, g []guid.GUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.putErr != nil {
		return m.putErr
	}
	for _, x := range g {
		if !slices.Contains(m.pins, x) {
			m.pins = append(m.pins, x)
		}
	}
	return nil
}

// T-0345 / TM-D26 rule 10: every Classify carries the persisted pins, and what a snapshot finds is
// pinned before the answer, so a rename after this call cannot lose it.
func TestADProviderPlumbsPinnedC13(t *testing.T) {
	ctx := context.Background()
	p, _, user, _ := adRig(t)
	pins := p.Pins.(*memPins)
	pins.pins = []guid.GUID{mk(80)}
	var seen [][]guid.GUID
	p.classify = func(_ context.Context, id guid.GUID, in tier0.ADInput) (tier0.ADResult, error) {
		seen = append(seen, in.PinnedC13)
		return tier0.ADResult{GUID: id, C13Groups: []guid.GUID{mk(81)}}, nil
	}
	for i := 0; i < 2; i++ {
		if _, err := p.Classify(ctx, user, nil); err != nil {
			t.Fatal(err)
		}
	}
	if len(seen) != 2 || !slices.Contains(seen[0], mk(80)) || !slices.Contains(seen[1], mk(81)) {
		t.Fatalf("pins passed = %v", seen)
	}
	// Fail closed: no store, an unreadable store, an unwritable store.
	p.Pins = nil
	if v, err := p.Classify(ctx, user, nil); err == nil || !v.Tier0 {
		t.Errorf("no store: %+v %v", v, err)
	}
	p.Pins = &memPins{getErr: errors.New("db down")}
	if v, err := p.Classify(ctx, user, nil); err == nil || !v.Tier0 {
		t.Errorf("read error: %+v %v", v, err)
	}
	p.Pins = &memPins{putErr: errors.New("db down")}
	if v, err := p.Classify(ctx, user, nil); err == nil || !v.Tier0 {
		t.Errorf("write error: %+v %v", v, err)
	}
}

// The default classifier path hands the pins to the classifier: a pinned group that was renamed is
// still tier0 with basis C13 (TM-D26 rule 10), here with a minimal forest. That the guard refuses a
// tier0 verdict at the live re-read is the write handler's test (fakeProv).
func TestADProviderRenamedPinnedGroupIsTier0(t *testing.T) {
	g := mk(90)
	pins := &memPins{pins: []guid.GUID{g}}
	p := &ADProvider{Pins: pins, ID: adIdentity()}
	p.classify = func(_ context.Context, id guid.GUID, in tier0.ADInput) (tier0.ADResult, error) {
		if slices.Contains(in.PinnedC13, id) { // what the classifier does with a pinned GUID whatever its name
			return tier0.ADResult{GUID: id, Tier0: true, Bases: []provider.Basis{tier0.C13}}, nil
		}
		return tier0.ADResult{GUID: id}, nil
	}
	p.Dir = &designatedDir{objs: map[guid.GUID]*adconn.Entry{g: adconn.NewEntry("CN=NetOps,DC=lab",
		map[string][][]byte{"objectClass": {[]byte("group")}, "cn": {[]byte("NetOps")}})}, errs: map[guid.GUID]error{}}
	v, err := p.Classify(context.Background(), g, nil)
	if err != nil || !v.Tier0 || len(v.Bases) != 1 || v.Bases[0] != tier0.C13 {
		t.Fatalf("%+v %v", v, err)
	}
}

// T-0345 review finding 1/2: the input the production path builds carries BOTH the pins and the
// designations, so C18 closes over designated objects on the write path. Dropping either field fails.
func TestADProviderClassifierInputCarriesPinsAndDesignations(t *testing.T) {
	ctx := context.Background()
	p, _, user, grp := adRig(t)
	p.Pins.(*memPins).pins = []guid.GUID{mk(80)}
	var got tier0.ADInput
	p.classify = func(_ context.Context, id guid.GUID, in tier0.ADInput) (tier0.ADResult, error) {
		got = in
		return tier0.ADResult{GUID: id}, nil
	}
	if _, err := p.Classify(ctx, user, []guid.GUID{grp}); err != nil {
		t.Fatal(err)
	}
	if !got.CorrelationKnown || !slices.Contains(got.PinnedC13, mk(80)) {
		t.Errorf("pins missing from classifier input: %+v", got)
	}
	if len(got.Designated) != 1 {
		t.Fatalf("designations missing from classifier input: %+v", got)
	}
	if g, ok := got.Designated[0].GUID(); !ok || g != grp {
		t.Errorf("designated ref = %v", got.Designated[0])
	}
}

// T-0401 AC2: the production constructor builds Dir, Bound and the facets over the one session, and a
// provider whose binder sits on another session refuses to name a DC and fails every facet closed.
func TestADProviderShareOneSession(t *testing.T) {
	s1, s2 := &adconn.Session{}, &adconn.Session{}
	p := NewADProvider(s1, nil, adIdentity(), &memPins{})
	if p.Dir.(tier0.SessionDirectory).S != s1 || p.Bound.(SessionDC).S != s1 || p.sess != s1 {
		t.Fatal("constructor did not share the session")
	}
	if !p.sameSession() || !p.OverSession(s1) || !p.sessionOK() {
		t.Fatal("constructed provider reports a session mismatch")
	}
	p.Bound = SessionDC{S: s2}
	if p.sameSession() || p.OverSession(s1) || p.sessionOK() {
		t.Fatal("mismatch undetected")
	}
	if _, err := p.BoundDC(context.Background()); !errors.Is(err, provider.ErrNoBoundDC) {
		t.Fatalf("mismatched binder answered: %v", err)
	}
	// Every facet fails closed on the mismatched provider (the Read pin).
	ctx := context.Background()
	if _, err := p.Read(ctx, mk(1), []string{"cn"}, 0); !errors.Is(err, provider.ErrNoBoundDC) {
		t.Errorf("Read: %v", err)
	}
	if _, _, err := p.Parent(ctx, nil); !errors.Is(err, provider.ErrNoBoundDC) {
		t.Errorf("Parent: %v", err)
	}
	if _, err := p.CanonicalAttr("cn"); !errors.Is(err, provider.ErrNoBoundDC) {
		t.Errorf("CanonicalAttr: %v", err)
	}
	if _, ok := p.Syntax("cn"); ok {
		t.Error("Syntax answered")
	}
	if _, err := p.ParseFilter(nil); !errors.Is(err, provider.ErrNoBoundDC) {
		t.Errorf("ParseFilter: %v", err)
	}
	if _, err := p.ScopedSearch(ctx, adconn.ScopedRequest{}, nil); !errors.Is(err, provider.ErrNoBoundDC) {
		t.Errorf("ScopedSearch: %v", err)
	}
	if p.RightsDirectory() != nil {
		t.Error("rights directory served by a mismatched provider")
	}
}

// A struct-literal provider has no session, hence no facets: the zero value fails every Read.
func TestADProviderLiteralHasNoFacets(t *testing.T) {
	p := &ADProvider{ID: adIdentity(), Pins: &memPins{}}
	if p.sessionOK() || p.RightsDirectory() != nil {
		t.Fatal("literal provider has facets")
	}
	if _, err := p.Read(context.Background(), mk(1), []string{"cn"}, 0); !errors.Is(err, provider.ErrNoBoundDC) {
		t.Fatalf("Read: %v", err)
	}
}

// The Describe rows follow the facets (AC4).
func TestSupportsFollowsFacets(t *testing.T) {
	p := NewADProvider(&adconn.Session{}, nil, adIdentity(), &memPins{})
	want := map[connectorv1.Operation]connectorv1.SupportState{
		connectorv1.Operation_OPERATION_VERIFY_CONNECTION: connectorv1.SupportState_SUPPORT_STATE_SUPPORTED,
		connectorv1.Operation_OPERATION_READ:              connectorv1.SupportState_SUPPORT_STATE_SUPPORTED,
		connectorv1.Operation_OPERATION_SCOPED_SEARCH:     connectorv1.SupportState_SUPPORT_STATE_SUPPORTED,
	}
	got := provider.Supports(p)
	if len(got) != len(want) {
		t.Fatalf("%v", got)
	}
	for _, r := range got {
		if want[r.GetOperation()] != r.GetState() {
			t.Errorf("%s = %s", r.GetOperation(), r.GetState())
		}
	}
}
