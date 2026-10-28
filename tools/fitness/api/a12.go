package main

import (
	"fmt"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"
)

var rateClasses = map[string]bool{"read": true, "write": true, "bulk": true, "auth": true, "reveal": true, "secret": true, "anonymous": true}

const (
	miB            = 1 << 20
	largeBodyCap   = 16 * miB
	secretBodyCap  = 64 << 10
	defaultBodyCap = 1 * miB
)

// limitClass is the class an operation declares in x-activediq-limits ("" when it takes the default).
func limitClass(o operation) string {
	return scalar(get(get(o.node, "x-activediq-limits"), "class"))
}

// requestBody returns the resolved request body of an operation.
func (t *tree) requestBody(o operation) (*yaml.Node, *srcFile) {
	rb := get(o.node, "requestBody")
	if rb == nil {
		return nil, o.file
	}
	n, f, ok := t.resolve(o.file, rb)
	if !ok {
		return nil, o.file
	}
	return n, f
}

// reachesSecretInput reports a request schema that carries x-activediq-secret (rule 6: SecretInput).
func (t *tree) reachesSecretInput(o operation) bool {
	rb, f := t.requestBody(o)
	if rb == nil {
		return false
	}
	found := false
	seen := map[*yaml.Node]bool{}
	for _, m := range mediaSchemas(get(rb, "content")) {
		if m.schema != nil {
			t.walkSchema(f, m.schema, seen, func(s *yaml.Node, _ *srcFile) {
				if scalar(get(s, "x-activediq-secret")) == "true" {
					found = true
				}
			}, nil)
		}
	}
	return found
}

// isUpload reports a request body that is not JSON (a binary or CSV upload) or whose schema is a binary string.
func (t *tree) isUpload(o operation) (media string, upload bool) {
	rb, f := t.requestBody(o)
	if rb == nil {
		return "", false
	}
	for _, m := range mediaSchemas(get(rb, "content")) {
		if m.name != "application/json" && !strings.HasSuffix(m.name, "+json") {
			return m.name, true
		}
		bin := false
		if m.schema != nil {
			t.walkSchema(f, m.schema, map[*yaml.Node]bool{}, func(s *yaml.Node, _ *srcFile) {
				if scalar(get(s, "format")) == "binary" || scalar(get(s, "contentEncoding")) != "" {
					bin = true
				}
			}, nil)
		}
		if bin {
			return m.name + " (binary)", true
		}
	}
	return "", false
}

// checkA12 enforces rule 10 on the document: declared rate classes and body caps.
func checkA12(t *tree) []Violation {
	var vs []Violation
	add := func(pos, f string, a ...any) {
		vs = append(vs, Violation{"A12", pos, fmt.Sprintf(f, a...)})
	}
	large := t.policyOps("largeBodies")
	secretResp := t.policyOps("secretResponses")

	for _, o := range t.ops {
		lim := get(o.node, "x-activediq-limits")
		class := limitClass(o)
		var maxBytes int64 = -1
		if lim != nil {
			if lim.Kind != yaml.MappingNode {
				add(o.where(), "%s: x-activediq-limits must be an object {class, maxBodyBytes} (ADR-0004 rule 10, A12)", o.label())
			}
			for i := 0; lim.Kind == yaml.MappingNode && i+1 < len(lim.Content); i += 2 {
				if k := lim.Content[i].Value; k != "class" && k != "maxBodyBytes" {
					add(o.where(), "%s: x-activediq-limits has unknown member %q (class and maxBodyBytes only) (ADR-0004 rule 10, A12)", o.label(), k)
				}
			}
			if mb := get(lim, "maxBodyBytes"); mb != nil {
				n, err := strconv.ParseInt(scalar(mb), 10, 64)
				if err != nil || n <= 0 {
					add(o.where(), "%s: maxBodyBytes %q is not a positive integer (ADR-0004 rule 10, A12)", o.label(), scalar(mb))
				} else {
					maxBytes = n
				}
			}
		}
		if class != "" && !rateClasses[class] {
			add(o.where(), "%s declares unknown rate class %q (read, write, bulk, auth, reveal, secret, anonymous) (ADR-0004 rule 10, A12)", o.label(), class)
		}
		if o.perm == "anonymous" && class != "anonymous" && class != "auth" {
			add(o.where(), "%s is anonymous but declares rate class %q: an anonymous operation declares anonymous or auth (ADR-0004 rule 10, A12)", o.label(), orDefault(class, "(default)"))
		}
		if media, up := t.isUpload(o); up && maxBytes < 0 {
			add(o.where(), "%s takes a %s upload with no maxBodyBytes: an upload declares its cap (ADR-0004 rule 10, A12)", o.label(), media)
		}
		if maxBytes > largeBodyCap {
			if _, ok := large[o.id]; !ok {
				add(o.where(), "%s declares maxBodyBytes %d, above 16 MiB, with no policy largeBodies entry (ADR-0004 rule 10, A12)", o.label(), maxBytes)
			}
		}
		if t.reachesSecretInput(o) {
			if _, both := secretResp[o.id]; !both && class != "secret" && !(o.perm == "anonymous" && class == "auth") {
				add(o.where(), "%s accepts a SecretInput but declares rate class %q, not secret (ADR-0004 rule 10, A12)", o.label(), orDefault(class, "(default)"))
			}
			switch {
			case maxBytes < 0:
				add(o.where(), "%s accepts a SecretInput and declares no maxBodyBytes: the default is 1 MiB, above the 64 KiB secret cap (ADR-0004 rule 6, A12)", o.label())
			case maxBytes > secretBodyCap:
				add(o.where(), "%s accepts a SecretInput with maxBodyBytes %d, above the 64 KiB secret cap (ADR-0004 rule 6, A12)", o.label(), maxBytes)
			}
			if media, up := t.isUpload(o); up {
				add(o.where(), "%s accepts a SecretInput in a %s body: a secret body is JSON, never binary (ADR-0004 rule 6, A12)", o.label(), media)
			}
		}
	}
	return append(vs, checkA12AN8(t)...)
}

// an8Statuses are the response codes an AN-8 operation may declare (authn.yaml).
var an8Statuses = map[string]bool{"204": true, "400": true, "401": true, "413": true, "415": true, "429": true, "500": true, "501": true}

// checkA12AN8 enforces threat model 7.6 rule 2 (T-0359, T-0497): an AN-8 operation never answers a
// per-account 429. The only 429 it may declare is the shared RateLimited response, and its description
// must say the source-IP limiter is the one that answers it. Any other shape (an inline response, a
// per-account response, a 429 added without that sentence) is refused, because a 429 that depends on
// the submitted name is an enumeration oracle.
func checkA12AN8(t *tree) []Violation {
	var vs []Violation
	for _, o := range t.ops {
		if scalar(get(o.node, "x-activediq-anonymous")) != "AN-8" {
			continue
		}
		rs := get(o.node, "responses")
		if rs != nil {
			// Only the statuses authn.yaml lists may appear. A 4XX or default response is a way to
			// declare "too many attempts for this account" without the literal 429 key.
			for i := 0; i+1 < len(rs.Content); i += 2 {
				code := rs.Content[i].Value
				if !an8Statuses[code] {
					vs = append(vs, Violation{"A12", o.where(), fmt.Sprintf("%s (AN-8) declares response %q: AN-8 may declare only 204, 400, 401, 413, 415, 429, 500 and 501, so no 4XX or default can describe a per-account limit (threat model 7.6 rule 2d, A12)", o.label(), code)})
				}
			}
		}
		r := get(rs, "429")
		if r == nil {
			continue
		}
		if ref := scalar(get(r, "$ref")); !strings.HasSuffix(ref, "#/components/responses/RateLimited") {
			vs = append(vs, Violation{"A12", o.where(), fmt.Sprintf("%s (AN-8) declares a 429 that is not the shared RateLimited response: AN-8 answers 429 only from the source-IP limiter, never per account (threat model 7.6 rule 2d, A12)", o.label())})
		}
		if d := strings.ToLower(scalar(get(o.node, "description"))); !strings.Contains(d, "source-ip") {
			vs = append(vs, Violation{"A12", o.where(), fmt.Sprintf("%s (AN-8) declares a 429 but its description does not say it is the source-IP limiter (threat model 7.6 rule 2d, A12)", o.label())})
		}
	}
	return vs
}
