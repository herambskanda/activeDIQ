package report

type Fragment struct{ text string }

// SQL builds a Fragment; RP1 requires a constant argument at every call site.
func SQL(text string) Fragment { return Fragment{text: text} }
