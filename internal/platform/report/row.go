package report

// Row is one result row as the compiler's cursor yields it: the row key, one Cell per requested
// column in Query.Columns order, and one flag per Query.Hidden group (true: the row belongs to that
// hidden group, so the run counts it and does not store it, contract §5).
type Row struct {
	Key    string
	Cells  []Cell
	Hidden []bool
}
