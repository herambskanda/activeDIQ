package store

// ChangesSessionSetting reports whether one statement, given as the upper-case words of a
// Statements entry (quoted text is already blanked), changes a session or transaction setting a
// guard has to care about: any set_config call (its setting name is a literal the scanner blanks, so
// every call counts), a mention of transaction_read_only or default_transaction_read_only, a mention
// of client_encoding, or SET NAMES (which switches client_encoding). The words come from a
// whole-statement split, so a mention in a column or alias name counts too: the check is a
// deliberate over-approximation for a read-only Plan, which has no reason to name them.
//
// It lives here because this package owns every statement that sets session state (the tenancy
// fitness job allows that SQL text only in internal/platform/store); operationtest calls it instead
// of spelling those names itself.
func ChangesSessionSetting(words []string) bool {
	for i, w := range words {
		switch w {
		case "SET_CONFIG", "TRANSACTION_READ_ONLY", "DEFAULT_TRANSACTION_READ_ONLY", "CLIENT_ENCODING":
			return true
		case "NAMES":
			if i > 0 && words[0] == "SET" {
				return true
			}
		}
	}
	return false
}
