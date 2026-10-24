package sd

import (
	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/attr/sid"
)

// ACE types (MS-DTYP 2.4.4.1).
const (
	TypeAccessAllowed         = 0x00
	TypeAccessDenied          = 0x01
	TypeSystemAudit           = 0x02
	TypeAccessAllowedObject   = 0x05
	TypeAccessDeniedObject    = 0x06
	TypeSystemAuditObject     = 0x07
	TypeAllowedCallback       = 0x09
	TypeDeniedCallback        = 0x0A
	TypeAllowedCallbackObject = 0x0B
	TypeDeniedCallbackObject  = 0x0C
	TypeAuditCallback         = 0x0D
	TypeAuditCallbackObject   = 0x0F
	TypeMandatoryLabel        = 0x11
	TypeResourceAttribute     = 0x12
	TypeScopedPolicyID        = 0x13
)

// AceFlags (MS-DTYP 2.4.4.1, plus Win32 CRITICAL_ACE_FLAG).
const (
	FlagObjectInherit      = 0x01
	FlagContainerInherit   = 0x02
	FlagNoPropagateInherit = 0x04
	FlagInheritOnly        = 0x08
	FlagInherited          = 0x10
	FlagCritical           = 0x20
	FlagSuccessfulAccess   = 0x40
	FlagFailedAccess       = 0x80
)

// Access mask bits used by the helper (MS-ADTS access rights).
const (
	MaskCreateChild   = 0x00000001
	MaskDeleteChild   = 0x00000002
	MaskListContents  = 0x00000004
	MaskSelf          = 0x00000008
	MaskReadProp      = 0x00000010
	MaskWriteProp     = 0x00000020
	MaskDeleteTree    = 0x00000040
	MaskListObject    = 0x00000080
	MaskControlAccess = 0x00000100
	MaskDelete        = 0x00010000
	MaskReadControl   = 0x00020000
	MaskWriteDACL     = 0x00040000
	MaskWriteOwner    = 0x00080000

	maskGeneric = 0xF0000000 // GR, GW, GX, GA: never stored in AD
)

// Kind is the decoded shape of an ACE.
type Kind uint8

const (
	// Basic is mask + trustee (types 0x00, 0x01, 0x02, 0x11, 0x12, 0x13).
	Basic Kind = iota
	// Object is mask + object flags + optional GUIDs + trustee (0x05, 0x06, 0x07).
	Object
	// Callback is a conditional ACE (0x09-0x0D, 0x0F): decoded, never evaluated.
	Callback
	// Opaque is an unknown or reserved type: preserved byte for byte, never interpreted.
	Opaque
)

// ACE is one access-control entry. It is a value; the zero value is not a decoded ACE.
type ACE struct {
	Kind  Kind
	Type  uint8
	Flags uint8
	// Mask, Trustee are set for Basic, Object and Callback ACEs.
	Mask    uint32
	Trustee sid.SID
	// ObjectType and InheritedObjectType are set for object-form ACEs when present on the wire.
	ObjectType          *guid.GUID
	InheritedObjectType *guid.GUID
	// Raw is the ACE exactly as stored, header included.
	Raw []byte
}

// Inherited reports the INHERITED flag.
func (a ACE) Inherited() bool { return a.Flags&FlagInherited != 0 }

// InheritOnly reports INHERIT_ONLY: the ACE does not apply to the object that holds it.
func (a ACE) InheritOnly() bool { return a.Flags&FlagInheritOnly != 0 }

// Allow and Deny report the DACL decision types the helper evaluates.
func (a ACE) allow() bool {
	return a.Kind != Callback && a.Kind != Opaque && (a.Type == TypeAccessAllowed || a.Type == TypeAccessAllowedObject)
}
func (a ACE) deny() bool {
	return a.Kind != Callback && a.Kind != Opaque && (a.Type == TypeAccessDenied || a.Type == TypeAccessDeniedObject)
}

// daclType and saclType say where MS-DTYP 2.4.5 allows a type. Reserved and unknown types are in neither.
func daclType(t uint8) bool {
	switch t {
	case 0x00, 0x01, 0x05, 0x06, 0x09, 0x0A, 0x0B, 0x0C:
		return true
	}
	return false
}

func saclType(t uint8) bool {
	switch t {
	case 0x02, 0x07, 0x0D, 0x0F, 0x11, 0x12, 0x13:
		return true
	}
	return false
}

// objectForm reports types whose body carries the object-ACE flags word.
func objectForm(t uint8) bool {
	switch t {
	case 0x05, 0x06, 0x07, 0x0B, 0x0C, 0x0F:
		return true
	}
	return false
}

func callbackType(t uint8) bool { return t >= 0x09 && t <= 0x0F && t != 0x0E }

func auditType(t uint8) bool {
	switch t {
	case 0x02, 0x07, 0x0D, 0x0F:
		return true
	}
	return false
}
