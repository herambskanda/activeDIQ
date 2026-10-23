package dn

type DNString string

func (d DNString) Display() string { return string(d) }

type DN struct{ s string }

func (d DN) Render() DNString { return DNString(d.s) }
func (d DN) String() string   { return d.s }

type ObjectRef struct{ d DN }

func DNRef(d DN) ObjectRef { return ObjectRef{d} }

func (r ObjectRef) ForRequest() (string, error) { return r.d.s, nil }
