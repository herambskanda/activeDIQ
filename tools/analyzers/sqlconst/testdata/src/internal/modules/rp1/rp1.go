package rp1

import (
	"encoding/json"

	"internal/platform/report"
	"internal/platform/store/reportsql"
)

const col = "{t}.enabled"

type alias = reportsql.CompiledSQL

func mint(userText string, raw []byte) {
	_ = reportsql.CompiledSQL(userText) // want `RP1.*conversion to reportsql.CompiledSQL`
	_ = alias(userText)                 // want `RP1.*conversion to reportsql.CompiledSQL`
	var c reportsql.CompiledSQL
	_ = json.Unmarshal(raw, &c)     // want `RP1.*address of a reportsql.CompiledSQL`
	_ = reportsql.Query{}           // want `RP1.*composite literal of reportsql.Query`
	_ = &reportsql.Query{}          // want `RP1.*composite literal of reportsql.Query`
	_ = []reportsql.Query{{}}       // want `RP1.*composite literal of reportsql.Query`
	_ = reportsql.Compile(userText) // the compiler is the producer: allowed
	_ = c                           // reading a CompiledSQL is allowed
}

func fragments(name string) {
	_ = report.SQL("{t}.disabled = false")
	_ = report.SQL(col)
	_ = report.SQL("{t}." + "enabled")
	_ = report.SQL(name)          // want `RP1.*report.SQL takes a compile-time constant`
	_ = report.SQL("{t}." + name) // want `RP1.*report.SQL takes a compile-time constant`
}
