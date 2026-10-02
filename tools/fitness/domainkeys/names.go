package main

import (
	"regexp"
	"strings"
)

// Identity strings (X3): a DN, SID, sAMAccountName, UPN or display name is never a key, a foreign key
// or a join column on a directory table. The rule reads the column's name; a column that does not
// look like one but holds one is annotated `COMMENT ON COLUMN … IS 'diq:holds=dn'` (dn, sid, sam, upn
// or name), which the rule honours whatever the column is called.

var (
	tokenSplit   = regexp.MustCompile(`[^a-z0-9]+`)
	identifier   = regexp.MustCompile(`[A-Za-z_][A-Za-z0-9_]*`)
	holdsComment = regexp.MustCompile(`diq:holds=(dn|sid|sam|upn|name)\b`)
	attrComment  = regexp.MustCompile(`diq:attr=([A-Za-z0-9-]+)`)
)

// identityPhrases are runs of tokens that name an identity string; a lone token `name` does too.
var identityPhrases = []struct {
	phrase string
	holds  string
}{
	{"distinguished name", "dn"}, {"distinguishedname", "dn"},
	{"sam account name", "sam"}, {"samaccountname", "sam"},
	{"user principal name", "upn"}, {"userprincipalname", "upn"},
	{"display name", "name"}, {"displayname", "name"},
	{"common name", "name"}, {"commonname", "name"},
	{"object sid", "sid"}, {"objectsid", "sid"},
}

// identityToken are single tokens: dn, sid, upn, cn, name. `dn_` and `_sid` count; `dns` and `did` do not.
var identityToken = map[string]string{"dn": "dn", "sid": "sid", "upn": "upn", "cn": "name", "name": "name"}

// identityHolds reports which identity string a column name says it holds, or "".
func identityHolds(col string) string {
	col = strings.ToLower(col)
	toks := tokenSplit.Split(col, -1)
	joined := " " + strings.Join(toks, " ") + " "
	for _, p := range identityPhrases {
		if strings.Contains(joined, " "+p.phrase+" ") || strings.Contains(strings.ReplaceAll(joined, " ", ""), strings.ReplaceAll(p.phrase, " ", "")) {
			return p.holds
		}
	}
	for _, t := range toks {
		if h, ok := identityToken[t]; ok {
			return h
		}
	}
	return ""
}

// keyHolds reports which identity string one key element holds: a column name, or an index
// expression (`lower(dn)`) whose identifiers are read the same way. comment is the column's comment.
func keyHolds(element, comment string) (holds string, byName bool) {
	if m := holdsComment.FindStringSubmatch(comment); m != nil {
		return m[1], false
	}
	for _, id := range identifier.FindAllString(element, -1) {
		if h := identityHolds(id); h != "" {
			return h, true
		}
	}
	return "", false
}

// State columns (X5): an append-only record has no lifecycle-state column; its states are derived.
var (
	stateWord   = regexp.MustCompile(`^(state|status|phase|stage|lifecycle)$`)
	stateSuffix = regexp.MustCompile(`_(state|status|phase|stage|lifecycle)$`)
	statePrefix = regexp.MustCompile(`^(state|status|phase|lifecycle)_`)
)

func stateName(s string) bool {
	s = strings.ToLower(s)
	return stateWord.MatchString(s) || stateSuffix.MatchString(s) || statePrefix.MatchString(s)
}

// normalise lower-cases and drops everything but letters and digits: ms-Mcs-AdmPwd and ms_mcs_admpwd
// both become msmcsadmpwd.
func normalise(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// minContainLen is the shortest normalised attribute name that is matched inside a longer column name
// (`old_unicode_pwd`, `ms_mcs_admpwd_cache`); shorter ones must match exactly, so a seven-letter
// attribute does not flag unrelated words.
const minContainLen = 8

// secretAttrFor reports which SecretAttrs attribute a column is named for, or "". A `diq:attr=`
// comment on the column names one explicitly. The attribute set comes from the caller.
func secretAttrFor(col, comment string, attrs []string) string {
	if m := attrComment.FindStringSubmatch(comment); m != nil {
		for _, a := range attrs {
			if normalise(a) == normalise(m[1]) {
				return a
			}
		}
	}
	c := normalise(col)
	for _, a := range attrs {
		n := normalise(a)
		if c == n || len(n) >= minContainLen && strings.Contains(c, n) {
			return a
		}
	}
	return ""
}
