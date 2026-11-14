package showdeleted

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"
)

// rec collects what analysistest would fail the test with, so a fixture can assert a diagnostic.
type rec struct{ msgs []string }

func (r *rec) Errorf(f string, a ...any) { r.msgs = append(r.msgs, fmt.Sprintf(f, a...)) }

const ldapStub = `package ldap
type Control interface{ GetControlType() string }
const ScopeBaseObject, ScopeSingleLevel, ScopeWholeSubtree = 0, 1, 2
type PagingControl struct{}
func (PagingControl) GetControlType() string { return "" }
func NewControlPaging(n uint32) *PagingControl { return &PagingControl{} }
type ModifyRequest struct{}
func NewModifyRequest(dn string, c []Control) *ModifyRequest { return nil }
`

const dnStub = `package dn
type DN struct{}
func (DN) String() string { return "" }
func (DN) Len() int { return 0 }
type ObjectRef struct{}
func GUIDRef(g [16]byte) ObjectRef { return ObjectRef{} }
func DNRef(d DN) ObjectRef { return ObjectRef{} }
func WKGUIDRef(g string) ObjectRef { return ObjectRef{} }
`

const scopeStub = `package scope
import "ldap"
type sd struct{}
func (sd) GetControlType() string { return "" }
func ShowDeleted() ldap.Control { return sd{} }
func Paged() ldap.Control { return sd{} }
`

// adTpl is the shape of the real internal/connector/ad sites, reduced to what the pass inspects.
// Each fixture replaces one marked fragment.
const adTpl = `package ad
import ("context"; "ldap"; "internal/connector/ad/scope"; "internal/directory/dn")

type ReadOptions struct{ showDeleted, ShowDeactivatedLink, ExtendedDN bool; SD SDFlags }
type SDPart uint8
const (SDOwner SDPart = 1; SDGroup SDPart = 2; SDDACL SDPart = 4; SDSACL SDPart = 8)
type SDFlags struct{}
func (SDFlags) control() ldap.Control { return nil }
func NewSDFlags(p ...SDPart) (SDFlags, error) { return SDFlags{}, nil }
func DefaultSDFlags() SDFlags { return SDFlags{} }
type Entry struct{}
func (*Entry) Strings(string) []string { return nil }
type ObjectState struct{}
type Session struct{}
type Tx struct{}
const WKGUIDDeletedObjects = "18e2ea80684f11d2b9aa00c04f79f805"
var deletedTargetAttrs = []string{"objectGUID"}
var stateAttrs = []string{"objectGUID"}
var objectClassPresent = "(objectClass=*)"
func wellKnownDN([]string, string) (dn.DN, bool, error) { return dn.DN{}, true, nil }
func (s *Session) Read(ctx context.Context, r dn.ObjectRef, a []string, o ReadOptions) (*Entry, error) { return nil, nil }
func (s *Session) searchOnceLocked(ctx context.Context, base string, sc int, f string, a []string, c []ldap.Control) (int, error) { return 0, nil }
func (s *Session) stateOf(e *Entry) (ObjectState, error) { return ObjectState{}, nil }
func (s *Session) RestoreObject(ctx context.Context) error { _, _ = s.readDeletedLocked(ctx); _ = scope.ShowDeleted(); return nil }
func (s *Session) readDeletedLocked(ctx context.Context) (int, error) { _ = scope.ShowDeleted(); return 0, nil }
func (t *Tx) ReadDeleted() { _ = scope.ShowDeleted() }
func dirSyncControls() []ldap.Control { return []ldap.Control{scope.ShowDeleted()} }
func visibilityControls(o ReadOptions) []ldap.Control { if o.showDeleted { return []ldap.Control{scope.ShowDeleted()} }; return nil }

func (s *Session) ReadDeletedTarget(ctx context.Context, id [16]byte) (*Entry, error) {
	return s.Read(ctx, /*B1REF*/dn.GUIDRef(id), /*B1ATTRS*/deletedTargetAttrs, /*B1OPTS*/ReadOptions{showDeleted: true, ShowDeactivatedLink: true, ExtendedDN: true, SD: DefaultSDFlags()})
}

func (s *Session) DeletedObjectState(ctx context.Context, id [16]byte) (ObjectState, error) {
	e, err := s.Read(ctx, dn.GUIDRef(id), stateAttrs, ReadOptions{showDeleted: true})
	if err != nil { return ObjectState{}, err }
	return s.stateOf(e)
}

func (s *Session) DeletedContainerDescriptor(ctx context.Context, domain dn.DN) (dn.DN, []byte, error) {
	head, err := s.Read(ctx, dn.DNRef(domain), []string{"wellKnownObjects"}, ReadOptions{})
	if err != nil { return dn.DN{}, nil, err }
	_ = head
	container, _, err := wellKnownDN(nil, WKGUIDDeletedObjects)
	flags, err := NewSDFlags(/*B2SD*/SDOwner, SDDACL)
	if err != nil { return dn.DN{}, nil, err }
	_, err = s.searchOnceLocked(ctx, container.String(), /*B2SCOPE*/ldap.ScopeBaseObject, objectClassPresent,
		/*B2ATTRS*/[]string{"nTSecurityDescriptor"}, /*B2CTRL*/[]ldap.Control{flags.control(), scope.ShowDeleted()})
	return container, nil, err
}
/*EXTRA*/
`

const writeTpl = `package write
import ("context"; "internal/connector/ad")

type StructureDirectory interface {
	DeletedTarget(ctx context.Context, id [16]byte) (*ad.Entry, error)
	DeletedContainer(ctx context.Context, d int) (int, []byte, error)
	DeletedState(ctx context.Context, id [16]byte) (ad.ObjectState, error)
	Restore(ctx context.Context) error
}
type SessionObjects struct{ S *ad.Session }
func (o SessionObjects) DeletedTarget(ctx context.Context, id [16]byte) (*ad.Entry, error) { return o.S.ReadDeletedTarget(ctx, id) }
func (o SessionObjects) DeletedContainer(ctx context.Context, d int) (int, []byte, error) { return 0, nil, nil }
func (o SessionObjects) DeletedState(ctx context.Context, id [16]byte) (ad.ObjectState, error) { return o.S.DeletedObjectState(ctx, id) }
func (o SessionObjects) Restore(ctx context.Context) error { return o.S.RestoreObject(ctx) }
type ADProvider struct{}
func (p *ADProvider) classifyDeleted(ctx context.Context, d StructureDirectory) { _, _ = d.DeletedTarget(ctx, [16]byte{}) }
func (p *ADProvider) proveListContents(ctx context.Context, d StructureDirectory) { _, _, _ = d.DeletedContainer(ctx, 0) }
func restoreState(ctx context.Context, d StructureDirectory) { _, _ = d.DeletedState(ctx, [16]byte{}) }
func applyRestore(ctx context.Context, d StructureDirectory) { _ = d.Restore(ctx); _, _ = d.DeletedState(ctx, [16]byte{}) }
/*EXTRA*/
`

func lay(t *testing.T, ad, write string) string {
	t.Helper()
	root := t.TempDir()
	for p, src := range map[string]string{
		"ldap/ldap.go":                         ldapStub,
		"internal/directory/dn/dn.go":          dnStub,
		"internal/connector/ad/scope/scope.go": scopeStub,
		"internal/connector/ad/ad.go":          ad,
		"internal/connector/write/write.go":    write,
	} {
		f := filepath.Join(root, "src", p)
		if err := os.MkdirAll(filepath.Dir(f), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(f, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func analyse(t *testing.T, ad, write string) []string {
	t.Helper()
	r := &rec{}
	analysistest.Run(r, lay(t, ad, write), Analyzer, "internal/connector/ad", "internal/connector/write")
	return r.msgs
}

func sub(s, mark, with string) string {
	i := strings.Index(s, "/*"+mark+"*/")
	if i < 0 {
		panic(mark)
	}
	// replace the marker and the fragment that follows it up to the next top-level delimiter
	rest := s[i+len(mark)+4:]
	j := 0
	depth := 0
	for ; j < len(rest); j++ {
		c := rest[j]
		if c == '(' || c == '{' || c == '[' {
			depth++
		} else if c == ')' || c == '}' || c == ']' {
			if depth == 0 {
				break
			}
			depth--
		} else if depth == 0 && (c == ',' || c == '\n') {
			break
		}
	}
	return s[:i] + with + rest[j:]
}

func TestGoodShapePasses(t *testing.T) {
	if m := analyse(t, strings.Replace(adTpl, "/*EXTRA*/", "", 1), strings.Replace(writeTpl, "/*EXTRA*/", "", 1)); len(m) != 0 {
		t.Fatalf("clean fixture reported: %v", m)
	}
}

func TestFailingFixtures(t *testing.T) {
	extraAD := func(src string) string { return strings.Replace(adTpl, "/*EXTRA*/", src, 1) }
	extraW := func(src string) string { return strings.Replace(writeTpl, "/*EXTRA*/", src, 1) }
	good := strings.Replace(adTpl, "/*EXTRA*/", "", 1)
	goodW := strings.Replace(writeTpl, "/*EXTRA*/", "", 1)
	cases := []struct{ name, ad, write, want string }{
		{"b2 one-level search on the container", sub(good, "B2SCOPE", "ldap.ScopeSingleLevel"), goodW, "base scope"},
		{"b2 subtree search with 417", sub(good, "B2SCOPE", "ldap.ScopeWholeSubtree"), goodW, "base scope"},
		{"b2 star attribute", sub(good, "B2ATTRS", `[]string{"*"}`), goodW, "exactly []string"},
		{"b2 empty attribute list", sub(good, "B2ATTRS", `[]string{}`), goodW, "exactly []string"},
		{"b2 an R2 attribute", sub(good, "B2ATTRS", `[]string{"nTSecurityDescriptor", "isDeleted"}`), goodW, "exactly []string"},
		{"b2 wrong SD flags (group)", strings.Replace(good, "SDOwner, SDDACL", "SDOwner, SDGroup, SDDACL", 1), goodW, "0x5 exactly"},
		{"b2 SACL bit", strings.Replace(good, "SDOwner, SDDACL", "SDOwner, SDDACL, SDSACL", 1), goodW, "0x5 exactly"},
		{"b2 wrong SD flags (owner only)", strings.Replace(good, "SDOwner, SDDACL", "SDOwner", 1), goodW, "0x5 exactly"},
		{"b2 paged results with 417", sub(good, "B2CTRL", "[]ldap.Control{flags.control(), scope.ShowDeleted(), scope.Paged()}"), goodW, "exactly the SD flags control"},
		{"b2 without 417 control order", sub(good, "B2CTRL", "[]ldap.Control{scope.ShowDeleted(), flags.control()}"), goodW, "second control"},
		{"b1 string DN", sub(good, "B1REF", `dn.DNRef(dn.DN{})`), goodW, "typed GUID reference"},
		{"b1 WKGUID DN", sub(good, "B1REF", `dn.WKGUIDRef("18e2")`), goodW, "typed GUID reference"},
		{"b1 another attribute list", sub(good, "B1ATTRS", `[]string{"*"}`), goodW, "fixed deletedTargetAttrs"},
		{"b1 SD flags other than default", sub(good, "B1OPTS", "ReadOptions{showDeleted: true, ShowDeactivatedLink: true, ExtendedDN: true}"), goodW, "SD is missing"},
		{"Session.Read with 417 elsewhere", extraAD(`func (s *Session) Report(ctx context.Context) { s.Read(ctx, dn.GUIDRef([16]byte{}), nil, ReadOptions{showDeleted: true}) }`), goodW, "showDeleted set outside"},
		{"subtree search with 417 in another function", extraAD(`func (s *Session) Sweep(ctx context.Context) { s.searchOnceLocked(ctx, "", ldap.ScopeWholeSubtree, "", nil, []ldap.Control{scope.ShowDeleted()}) }`), goodW, "outside a named construction site"},
		{"showDeleted assigned", extraAD(`func f(o *ReadOptions) { o.showDeleted = true }`), goodW, "assigned"},
		{"OID literal", extraAD(`var oid = "1.2.840.113556.1.4.417"`), goodW, "spelled out"},
		{"b1 called from a report", good, extraW(`func Report(ctx context.Context, s *ad.Session) { s.ReadDeletedTarget(ctx, [16]byte{}) }`), "caller allow-list"},
		{"b2 called from another kind", good, extraW(`func planMove(ctx context.Context, d StructureDirectory) { d.DeletedContainer(ctx, 0) }`), "caller allow-list"},
		{"b3 called from a handler", good, extraW(`func Handle(ctx context.Context, s *ad.Session) { s.DeletedObjectState(ctx, [16]byte{}) }`), "caller allow-list"},
		{"restore called from a job", good, extraW(`func Job(ctx context.Context, d StructureDirectory) { d.Restore(ctx) }`), "caller allow-list"},
		{"restore through the session from a job", good, extraW(`func Job(ctx context.Context, s *ad.Session) { s.RestoreObject(ctx) }`), "caller allow-list"},
		{"owner/DACL write beside the container read", good, extraW(`func SetContainerDACL(ctx context.Context, d StructureDirectory) { d.DeletedContainer(ctx, 0); ModifyDescriptor() }
func ModifyDescriptor() {}`), "no owner or DACL write"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			msgs := analyse(t, c.ad, c.write)
			if len(msgs) == 0 {
				t.Fatalf("no diagnostic: the fixture passed the check")
			}
			for _, m := range msgs {
				if strings.Contains(m, c.want) {
					return
				}
			}
			t.Fatalf("want a diagnostic containing %q, got %v", c.want, msgs)
		})
	}
}
