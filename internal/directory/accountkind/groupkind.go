package accountkind

import (
	"encoding/hex"
	"strings"

	"github.com/skenzeriq/activediq/internal/platform/operation/digest"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// Kinds 11 and 12 (contract §8.10.3, v1.6): add a member to a group, remove one. The target is the
// GROUP; the member is a GUID, never a DN. The digest covers the member's GUID and its declared class,
// so a plan for a user cannot be applied to a group.
const (
	KeyGroupMemberAdd    = "ad.group.addMember"
	KeyGroupMemberRemove = "ad.group.removeMember"
)

// Attribute names in the digest's Attrs of kinds 11 and 12.
const (
	AttrMember      = "member"      // canonical lower-case GUID text
	AttrMemberClass = "memberClass" // user, computer, contact or group
)

// ClassGroup and ClassContact are the digest labels for the other member classes.
const (
	ClassGroup   = "group"
	ClassContact = "contact"
)

var memberClasses = map[string]connectorv1.DirectoryObjectClass{
	ClassUser:     connectorv1.DirectoryObjectClass_DIRECTORY_OBJECT_CLASS_USER,
	ClassComputer: connectorv1.DirectoryObjectClass_DIRECTORY_OBJECT_CLASS_COMPUTER,
	ClassContact:  connectorv1.DirectoryObjectClass_DIRECTORY_OBJECT_CLASS_CONTACT,
	ClassGroup:    connectorv1.DirectoryObjectClass_DIRECTORY_OBJECT_CLASS_GROUP,
}

// MemberClassLabel is the digest spelling of a member class, or "" for one that is not allowed.
func MemberClassLabel(c connectorv1.DirectoryObjectClass) string {
	for l, v := range memberClasses {
		if v == c {
			return l
		}
	}
	return ""
}

// GroupSpec is one of kinds 11 and 12.
type GroupSpec struct {
	Key  string
	Kind connectorv1.WriteKind
}

var groupSpecs = []GroupSpec{
	{KeyGroupMemberAdd, connectorv1.WriteKind_WRITE_KIND_GROUP_MEMBER_ADD},
	{KeyGroupMemberRemove, connectorv1.WriteKind_WRITE_KIND_GROUP_MEMBER_REMOVE},
}

// GroupSpecs returns kinds 11 and 12.
func GroupSpecs() []GroupSpec { return append([]GroupSpec(nil), groupSpecs...) }

// GroupSpecByKey finds a group kind by its digest key.
func GroupSpecByKey(key string) (GroupSpec, bool) {
	for _, s := range groupSpecs {
		if s.Key == key {
			return s, true
		}
	}
	return GroupSpec{}, false
}

// IsGroupKey reports whether key is kind 11 or 12.
func IsGroupKey(key string) bool { _, ok := GroupSpecByKey(key); return ok }

// GroupChangeFromAttrs derives the typed change of kind 11 or 12 from the planned write's attributes.
// The attributes must be exactly {member, memberClass}.
func GroupChangeFromAttrs(key string, attrs []digest.Attr) (*connectorv1.WriteChange, error) {
	if !IsGroupKey(key) || len(attrs) != 2 {
		return nil, ErrAttrs
	}
	var member, class string
	var haveM, haveC bool
	for _, a := range attrs {
		if a.Secret || len(a.Values) != 1 {
			return nil, ErrAttrs
		}
		switch a.Name {
		case AttrMember:
			if haveM || !Canonical(a.Values[0]) {
				return nil, ErrAttrs
			}
			member, haveM = a.Values[0], true
		case AttrMemberClass:
			if haveC {
				return nil, ErrAttrs
			}
			class, haveC = a.Values[0], true
		default:
			return nil, ErrAttrs
		}
	}
	cl, ok := memberClasses[class]
	if !haveM || !haveC || !ok {
		return nil, ErrAttrs
	}
	g, err := guidWire(member)
	if err != nil {
		return nil, ErrAttrs
	}
	if key == KeyGroupMemberAdd {
		return &connectorv1.WriteChange{Change: &connectorv1.WriteChange_GroupMemberAdd{
			GroupMemberAdd: &connectorv1.GroupMemberAdd{Member: g, MemberClass: cl}}}, nil
	}
	return &connectorv1.WriteChange{Change: &connectorv1.WriteChange_GroupMemberRemove{
		GroupMemberRemove: &connectorv1.GroupMemberRemove{Member: g, MemberClass: cl}}}, nil
}

// GroupAttrsOf is the inverse: the digest attributes of a typed kind 11 or 12 change. A change that
// is not the key's arm, or has a member GUID or class outside the matrix, is ErrAttrs.
func GroupAttrsOf(key string, ch *connectorv1.WriteChange) ([]digest.Attr, error) {
	var g *connectorv1.Guid
	var c connectorv1.DirectoryObjectClass
	switch key {
	case KeyGroupMemberAdd:
		x := ch.GetGroupMemberAdd()
		if x == nil {
			return nil, ErrAttrs
		}
		g, c = x.GetMember(), x.GetMemberClass()
	case KeyGroupMemberRemove:
		x := ch.GetGroupMemberRemove()
		if x == nil {
			return nil, ErrAttrs
		}
		g, c = x.GetMember(), x.GetMemberClass()
	default:
		return nil, ErrAttrs
	}
	label := MemberClassLabel(c)
	text, err := guidText(g)
	if label == "" || err != nil {
		return nil, ErrAttrs
	}
	return []digest.Attr{
		{Name: AttrMember, Values: []string{text}},
		{Name: AttrMemberClass, Values: []string{label}},
	}, nil
}

// guidText renders a wire Guid (16 bytes, RFC 4122 order, as the server digests it).
func guidText(g *connectorv1.Guid) (string, error) {
	b := g.GetValue()
	if len(b) != 16 {
		return "", ErrAttrs
	}
	h := hex.EncodeToString(b)
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:], nil
}

// guidWire parses canonical lower-case text (the caller has checked Canonical).
func guidWire(text string) (*connectorv1.Guid, error) {
	b, err := hex.DecodeString(strings.ReplaceAll(text, "-", ""))
	if err != nil || len(b) != 16 {
		return nil, ErrAttrs
	}
	return &connectorv1.Guid{Value: b}, nil
}
