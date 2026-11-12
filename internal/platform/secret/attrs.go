package secret

// IsPlainAttrName reports whether name is a plain attribute descr: a letter, then letters, digits,
// hyphens or underscores (RFC 4512 §1.4 descr, without the ";option" suffix). A numericoid, an "OID."
// prefix, an ";binary" option, whitespace and control characters are all not plain. The directory
// accepts those as aliases of the same attribute, so a name-list check is only sound once every name
// is known to be a plain one.
func IsPlainAttrName(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z':
		case i > 0 && (c >= '0' && c <= '9' || c == '-' || c == '_'):
		default:
			return false
		}
	}
	return true
}
