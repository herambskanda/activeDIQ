package m

import (
	"internal/directory/odata"
	"internal/directory/odata/graphschema"
)

const set = "users"

func fx11(userInput string) odata.Segment {
	return odata.Seg(odata.Name(userInput)) // want `FF-SP2 \[odataname\]: odata.Name converted from a non-constant`
}

func okConstant() odata.Segment { return odata.Seg(odata.Name(set)) }

func okUntyped() odata.Segment { return odata.Seg("groups") }

func okSchema() odata.Prop[odata.String] { return graphschema.UserPrincipalName }

func declaresProp() odata.Prop[odata.String] {
	return odata.StringProp("mail") // want `FF-SP2 \[odataname\]: odata.StringProp outside graphschema`
}

type other string

func okOtherConversion(s string) other { return other(s) }
