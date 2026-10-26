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
	return vs
}
