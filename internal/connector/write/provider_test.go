package write

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/connector/ad"
	"github.com/skenzeriq/activediq/internal/connector/graph"
	"github.com/skenzeriq/activediq/internal/connector/tier0"
	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/attr/sid"
	"github.com/skenzeriq/activediq/internal/directory/dn"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// CC-WRITE-20 g: a GPO whose cn is not a GUID is tier0; ordinary objects are not touched by the rule.
func TestGPOCNMustBeAGUID(t *testing.T) {
	gpo := func(cn string) *ad.Entry {
		return ad.NewEntry("CN="+cn+",CN=Policies,CN=System,DC=lab,DC=test", map[string][][]byte{
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
	user := ad.NewEntry("CN=x,DC=lab,DC=test", map[string][][]byte{"objectClass": {[]byte("user")}, "cn": {[]byte("x")}})
	if gpoCNInvalid(user) {
		t.Error("a user is not subject to the GPO cn rule")
	}
}

// designatedDir is a minimal ADDirectory: Get answers per object GUID. The base classifier is
// substituted, so Naming and Find are never reached.
type designatedDir struct {
	tier0.ADDirectory
	objs map[guid.GUID]*ad.Entry
	errs map[guid.GUID]error
}

func (d *designatedDir) Get(_ context.Context, ref dn.ObjectRef, _ []string) (*ad.Entry, error) {
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
	return nil, &ad.Error{Code: ad.CodeObjectNotFound}
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
	d := &designatedDir{objs: map[guid.GUID]*ad.Entry{
		user: ad.NewEntry("CN=u,DC=lab", map[string][][]byte{"objectClass": {[]byte("user")}, "cn": {[]byte("u")},
			"tokenGroups": {sidBytes(t, "S-1-5-21-1-2-3-1100"), sidBytes(t, "S-1-5-21-1-2-3-513")}}),
		grp: ad.NewEntry("CN=g,DC=lab", map[string][][]byte{"objectSid": {sidBytes(t, "S-1-5-21-1-2-3-1100")}}),
	}, errs: map[guid.GUID]error{}}
	p := &ADProvider{Dir: d, Pins: &memPins{}}
	p.classify = func(_ context.Context, id guid.GUID, _ []guid.GUID) (tier0.ADResult, error) {
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
	d.objs[grp] = ad.NewEntry("CN=g,DC=lab", map[string][][]byte{"objectSid": {sidBytes(t, "S-1-5-21-1-2-3-1200")}})
	if v, err := p.Classify(ctx, user, []guid.GUID{grp}); err != nil || v.Tier0 {
		t.Fatalf("non-member: %+v %v", v, err)
	}
	// Any other read error is refused (Tier0 true with an error).
	d.errs[grp] = &ad.Error{Code: ad.CodeProtocol}
	if v, err := p.Classify(ctx, user, []guid.GUID{grp}); err == nil || !v.Tier0 {
		t.Fatalf("read error must fail closed: %+v %v", v, err)
	}
	delete(d.errs, grp)
	d.errs[user] = &ad.Error{Code: ad.CodeProtocol}
	if v, err := p.Classify(ctx, user, []guid.GUID{grp}); err == nil || !v.Tier0 {
		t.Fatalf("token read error must fail closed: %+v %v", v, err)
	}
}

func TestADProviderClassifierAnswersFailClosed(t *testing.T) {
	ctx := context.Background()
	p, _, user, _ := adRig(t)
	p.classify = func(context.Context, guid.GUID, []guid.GUID) (tier0.ADResult, error) {
		return tier0.ADResult{Unknown: true, Tier0: true, GUID: user}, nil
	}
	if v, err := p.Classify(ctx, user, nil); err == nil || !v.Tier0 {
		t.Fatalf("Unknown result: %+v %v", v, err)
	}
	p.classify = func(context.Context, guid.GUID, []guid.GUID) (tier0.ADResult, error) {
		return tier0.ADResult{GUID: mk(99)}, nil
	}
	if v, err := p.Classify(ctx, user, nil); err == nil || !v.Tier0 {
		t.Fatalf("GUID mismatch: %+v %v", v, err)
	}
	p.classify = func(context.Context, guid.GUID, []guid.GUID) (tier0.ADResult, error) {
		return tier0.ADResult{}, errors.New("dc down")
	}
	if v, err := p.Classify(ctx, user, nil); err == nil || !v.Tier0 {
		t.Fatalf("classifier error: %+v %v", v, err)
	}
}

// groupReader answers GroupMembers from a table; the classifier methods are never reached because
// the base classifier is not part of this test (Classify is exercised through membersOf).
type groupReader struct {
	tier0.Reader
	members map[guid.GUID][]graph.DirectoryObject
	err     map[guid.GUID]error
}

func (g groupReader) GroupMembers(_ context.Context, id guid.GUID) ([]graph.DirectoryObject, error) {
	if e := g.err[id]; e != nil {
		return nil, e
	}
	m, ok := g.members[id]
	if !ok {
		return nil, &graph.Error{Code: graph.CodeNotFound}
	}
	return m, nil
}

// An Entra direct member of a designated group is tier0; missing group skipped; other errors refuse.
func TestEntraDesignatedMembership(t *testing.T) {
	ctx := context.Background()
	user, grp := entraID(ePlain), mk(82)
	h, _, _ := entraRig(t)
	p := h.prov.(*EntraProvider)
	p.Reader = withMembers{p.Reader, groupReader{
		members: map[guid.GUID][]graph.DirectoryObject{entraID(eGroup): {}, grp: {{ID: user.String(), ODataType: "#microsoft.graph.user"}}},
		err:     map[guid.GUID]error{mk(80): errors.New("graph 500")}}}
	v, err := p.Classify(ctx, user, []guid.GUID{grp})
	if err != nil || !v.Tier0 || v.Bases[len(v.Bases)-1] != tier0.Designated {
		t.Fatalf("direct member: %+v %v", v, err)
	}
	if v, err := p.Classify(ctx, user, []guid.GUID{mk(81)}); err != nil || v.Tier0 {
		t.Fatalf("missing designated group: %+v %v", v, err)
	}
	if v, err := p.Classify(ctx, user, []guid.GUID{mk(80)}); err == nil || !v.Tier0 {
		t.Fatalf("read error must fail closed: %+v %v", v, err)
	}
	if v, err := p.Classify(ctx, entraID("77777777-7777-7777-7777-0000000000aa"), []guid.GUID{grp}); err != nil || v.Tier0 {
		t.Fatalf("non-member: %+v %v", v, err)
	}
}

// withMembers sends GroupMembers to the table and everything else to the live (fake Graph) reader.
type withMembers struct {
	tier0.Reader
	g groupReader
}

func (w withMembers) GroupMembers(ctx context.Context, id guid.GUID) ([]graph.DirectoryObject, error) {
	return w.g.GroupMembers(ctx, id)
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
	p.classify = func(_ context.Context, id guid.GUID, pin []guid.GUID) (tier0.ADResult, error) {
		seen = append(seen, pin)
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

// The default classifier path hands the pins to the real classifier: a renamed pinned group is
// refused at the handler (TM-D26 rule 10), here with a minimal forest.
func TestHandlerRefusesRenamedPinnedGroup(t *testing.T) {
	run := passRun(nil)
	r := newRig(t, &run)
	g := mk(90)
	pins := &memPins{pins: []guid.GUID{g}}
	p := &ADProvider{Pins: pins, ID: adIdentity()}
	p.classify = func(_ context.Context, id guid.GUID, pin []guid.GUID) (tier0.ADResult, error) {
		if slices.Contains(pin, id) { // what the classifier does with a pinned GUID whatever its name
			return tier0.ADResult{GUID: id, Tier0: true, Bases: []Basis{tier0.C13}}, nil
		}
		return tier0.ADResult{GUID: id}, nil
	}
	p.Dir = &designatedDir{objs: map[guid.GUID]*ad.Entry{g: ad.NewEntry("CN=NetOps,DC=lab",
		map[string][][]byte{"objectClass": {[]byte("group")}, "cn": {[]byte("NetOps")}})}, errs: map[guid.GUID]error{}}
	h, err := New(p, r.gate, WithRecorder(r.rec), WithClock(func() time.Time { return r.now }))
	if err != nil {
		t.Fatal(err)
	}
	for tname, tr := range transports(t, h) {
		_, err := tr.Plan(context.Background(), planReq(g, ctxFor(g)))
		d := wantTier0(t, err, connectorv1.Tier0RefusalStage_TIER0_REFUSAL_STAGE_LIVE_REREAD)
		if len(d.GetBasis()) != 1 || d.GetBasis()[0] != tier0.C13 {
			t.Errorf("%s: basis %v", tname, d.GetBasis())
		}
	}
}
