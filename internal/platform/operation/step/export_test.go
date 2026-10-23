package step

// testMinter returns a properly issued Minter for this package's tests without touching the
// take-once state.
func testMinter() *Minter { return &Minter{t: theIssued} }
