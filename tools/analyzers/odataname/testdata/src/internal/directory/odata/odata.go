package odata

type Name string
type String string
type Prop[V any] struct{ name Name }
type Segment struct{ n Name }

func StringProp(n Name) Prop[String] { return Prop[String]{n} }
func BoolProp(n Name) Prop[bool]     { return Prop[bool]{n} }
func Seg(n Name) Segment             { return Segment{n} }

// Inside the home a Name may be made from anything (the grammar check lives here).
func FromParsed(s string) Name { return Name(s) }
