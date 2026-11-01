package reportsql

type CompiledSQL string

type Query struct{ text CompiledSQL }

// Compile is the one producer: inside this package a conversion, the address of a CompiledSQL and a
// Query literal are allowed (RP1 judges every other package).
func Compile(identifier string) Query {
	c := CompiledSQL("SELECT " + identifier)
	_ = &c
	return Query{text: c}
}
