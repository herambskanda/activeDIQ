package sd

// Order rules (MS-DTYP 2.4.5, split by what they can change; safe-primitives-security-descriptor §1).
// Rules 1 and 2 change outcomes and gate editing. Rules 3 and 4 are cosmetic: a note only. Rule 5
// cannot be decided from the bytes and is never reported.

// OrderViolation is one ordering finding.
type OrderViolation struct {
	Rule  int
	Index int
}

// OrderReport separates the outcome-changing violations from the cosmetic ones.
type OrderReport struct {
	Outcome  []OrderViolation // rules 1 and 2
	Cosmetic []OrderViolation // rules 3 and 4
}

// Order reports the ordering rules a DACL breaks. A non-list ACL has none.
func (a ACL) Order() OrderReport {
	var r OrderReport
	if a.Kind != List {
		return r
	}
	sawInherited := false
	sawAllow := false
	scopedAllow, scopedDeny := false, false
	for i, e := range a.ACEs {
		if e.Inherited() {
			sawInherited = true
			continue
		}
		if sawInherited {
			r.Outcome = append(r.Outcome, OrderViolation{1, i})
			continue
		}
		if e.deny() && sawAllow {
			r.Outcome = append(r.Outcome, OrderViolation{2, i})
		}
		scoped := e.ObjectType != nil
		switch {
		case e.allow():
			sawAllow = true
			if scoped {
				scopedAllow = true
			} else if scopedAllow {
				r.Cosmetic = append(r.Cosmetic, OrderViolation{4, i})
			}
		case e.deny():
			if scoped {
				scopedDeny = true
			} else if scopedDeny {
				r.Cosmetic = append(r.Cosmetic, OrderViolation{3, i})
			}
		}
	}
	return r
}

func orderReport(a ACL) ([]Anomaly, []Note) {
	rep := a.Order()
	var an []Anomaly
	var notes []Note
	for _, v := range rep.Outcome {
		an = append(an, Anomaly{AnomalyOrderOutcome, v.Index, v.Rule})
	}
	for _, v := range rep.Cosmetic {
		notes = append(notes, Note{NoteOrderCosmetic, v.Index, v.Rule})
	}
	return an, notes
}
