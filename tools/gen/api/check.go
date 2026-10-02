package main

import (
	"sort"
)

// refsOf lists the component schemas one node refers to, directly or through its own inline
// array, map and member nodes. A union lists its variants.
func refsOf(s *Schema) []string {
	var out []string
	var walk func(n *Schema)
	walk = func(n *Schema) {
		if n == nil {
			return
		}
		if n.Ref != "" {
			out = append(out, n.Ref)
		}
		out = append(out, n.OneOf...)
		walk(n.Items)
		walk(n.AddlProps)
		names := make([]string, 0, len(n.Props))
		for k := range n.Props {
			names = append(names, k)
		}
		sort.Strings(names)
		for _, k := range names {
			walk(n.Props[k])
		}
	}
	walk(s)
	return out
}

// closure adds every schema reachable from roots to set.
func (m *Model) closure(roots []string, set map[string]bool) {
	stack := append([]string(nil), roots...)
	for len(stack) > 0 {
		n := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if set[n] {
			continue
		}
		s := m.Schemas[n]
		if s == nil {
			continue
		}
		set[n] = true
		stack = append(stack, refsOf(s)...)
	}
}

func (m *Model) check(p *parser) {
	// Reference integrity.
	for _, name := range sortedKeys(m.Schemas) {
		s := m.Schemas[name]
		for _, r := range refsOf(s) {
			if m.Schemas[r] == nil {
				p.fail(s.Where, "$ref names components/schemas/%s, which does not exist", r)
			}
		}
	}
	for _, op := range m.Ops {
		where := op.Method + " " + op.Path
		for _, pm := range op.Params {
			for _, r := range refsOf(pm.Schema) {
				if m.Schemas[r] == nil {
					p.fail(where, "parameter %q refers to missing components/schemas/%s", pm.Name, r)
				}
			}
		}
		if op.Body != nil && op.Body.Schema != nil && m.Schemas[op.Body.Schema.Ref] == nil {
			p.fail(where, "the request body refers to missing components/schemas/%s", op.Body.Schema.Ref)
		}
		for _, r := range op.Responses {
			if r.Schema != nil && m.Schemas[r.Schema.Ref] == nil {
				p.fail(where, "response %d refers to missing components/schemas/%s", r.Status, r.Schema.Ref)
			}
		}
	}
	if p.el.err() != nil {
		return // reachability over a broken graph only adds noise
	}

	// Reachability from Inputs and Outputs.
	var reqRoots, respRoots, patchRoots []string
	for _, op := range m.Ops {
		for _, pm := range op.Params {
			reqRoots = append(reqRoots, refsOf(pm.Schema)...)
		}
		if op.Body != nil && op.Body.Schema != nil {
			if op.Body.Media == mediaPatch {
				patchRoots = append(patchRoots, op.Body.Schema.Ref)
			} else {
				reqRoots = append(reqRoots, op.Body.Schema.Ref)
			}
		}
		for _, r := range op.Responses {
			if r.Schema != nil {
				respRoots = append(respRoots, r.Schema.Ref)
			}
		}
	}
	respRoots = append(respRoots, m.problemRoots...)
	m.closure(reqRoots, m.Req)
	m.closure(respRoots, m.Resp)
	patchSet := map[string]bool{}
	for _, r := range patchRoots {
		m.Patch[r] = true
		s := m.Schemas[r]
		if !s.isObject() {
			p.fail(s.Where, "a merge-patch body schema is an object")
			continue
		}
		for _, name := range sortedKeys(s.Props) {
			if s.Required[name] {
				p.fail(s.Where, "member %q is required, but every member of a merge-patch body is optional (RFC 7396)", name)
			}
		}
		if m.Req[r] || m.Resp[r] {
			p.fail(s.Where, "a merge-patch body schema is used only as a PATCH body; it is also reachable elsewhere")
		}
		// Opt[T] decodes through T's own decoder. An inline array or map would be decoded by v2's
		// built-in slice and map support, which turns a null item into a zero value (D-0014), so the
		// member names a schema, which has a generated decoder.
		for _, name := range sortedKeys(s.Props) {
			if ms := s.Props[name]; ms.Ref == "" && (ms.Type == "array" || ms.isMap()) {
				p.fail(s.Where+".properties."+name, "a merge-patch member that is an array or a map is a named schema under components/schemas (its generated decoder refuses null items)")
			}
		}
		// Members of the patch body are request-reachable ordinary types.
		for _, name := range sortedKeys(s.Props) {
			m.closure(refsOf(s.Props[name]), m.Req)
		}
		patchSet[r] = true
	}
	for r := range patchSet {
		m.Req[r] = true
	}

	for _, name := range sortedKeys(m.Schemas) {
		s := m.Schemas[name]
		m.checkSchema(p, s)
	}

	// Secret closure: schemas whose members can reach SecretInput.
	if si := m.Schemas["SecretInput"]; si != nil {
		if si.Type != "string" || !si.WriteOnly || !si.Secret || si.Tag != "" {
			p.fail(si.Where, "SecretInput is a shared string schema with writeOnly: true and x-activediq-secret: true")
		}
		m.SecretTy["SecretInput"] = true
		for changed := true; changed; {
			changed = false
			for _, name := range sortedKeys(m.Schemas) {
				if m.SecretTy[name] {
					continue
				}
				for _, r := range refsOf(m.Schemas[name]) {
					if m.SecretTy[r] {
						m.SecretTy[name] = true
						changed = true
						break
					}
				}
			}
		}
	}
	for _, name := range sortedKeys(m.Resp) {
		if m.SecretTy[name] && name != "SecretInput" {
			p.fail(m.Schemas[name].Where, "schema %s is reachable from a response and reaches SecretInput: a secret is write-only and never leaves the server (TM-F-SECRETOUT)", name)
		}
		if name == "SecretInput" && m.Resp[name] {
			p.fail(m.Schemas[name].Where, "SecretInput is reachable from a response: a secret is write-only")
		}
	}
	for _, op := range m.Ops {
		if op.Body != nil && op.Body.Schema != nil && m.SecretTy[op.Body.Schema.Ref] {
			op.Secret = true
		}
		for _, pm := range op.Params {
			for _, r := range refsOf(pm.Schema) {
				if m.SecretTy[r] {
					p.fail(op.Method+" "+op.Path, "parameter %q carries a secret: credentials never travel in a path, query or header parameter", pm.Name)
				}
			}
		}
		if op.Secret && op.Body.Binary {
			p.fail(op.Method+" "+op.Path, "a secret operation has no binary body")
		}
	}
}

// checkSchema runs the checks that need reachability.
func (m *Model) checkSchema(p *parser, s *Schema) {
	req, resp := m.Req[s.Name], m.Resp[s.Name]
	switch {
	case s.isObject():
		if req && !s.AddlFalse {
			p.fail(s.Where, "a request object declares additionalProperties: false")
		}
		if !req && !resp && !s.AddlFalse && !s.AddlTrue {
			// Unreferenced shared objects decode strictly too.
		}
		for _, name := range sortedKeys(s.Props) {
			ms := s.Props[name]
			if ms.Nullable && !s.Required[name] && !m.Patch[s.Name] {
				p.fail(s.Where+".properties."+name, "an optional nullable member is banned: absent and null would mean the same thing; make it required, or drop null (only a merge-patch member may be optional and nullable)")
			}
			if ms.Ref != "" && ms.Nullable {
				p.fail(s.Where+".properties."+name, "a nullable $ref is not expressible in the dialect")
			}
		}
	case s.isMap():
		if s.MaxProps == nil {
			p.fail(s.Where, "a map declares maxProperties")
		}
	case s.isEnum():
		switch {
		case req && resp:
			p.fail(s.Where, "an enum is reachable from requests or from responses, never both: a request enum is closed and a response enum is open; use two schemas")
		case resp && !s.EnumOpen:
			p.fail(s.Where, "an enum reachable from a response carries x-activediq-enum: open")
		case req && s.EnumOpen:
			p.fail(s.Where, "x-activediq-enum: open marks response enums; this one is reachable from requests only")
		}
	case s.isUnion():
		kinds := map[string]string{}
		for _, v := range s.OneOf {
			vs := m.Schemas[v]
			if vs == nil || !vs.isObject() {
				p.fail(s.Where, "oneOf variant %s is not an object schema", v)
				continue
			}
			ks := vs.Props["kind"]
			switch {
			case ks == nil || ks.Type != "string" || !ks.HasConst || !vs.Required["kind"]:
				p.fail(vs.Where, "a oneOf variant declares kind as a required single-value const")
			case kinds[ks.Const] != "":
				p.fail(vs.Where, "kind %q is also the kind of %s", ks.Const, kinds[ks.Const])
			default:
				kinds[ks.Const] = v
			}
		}
	}
	if s.Nullable {
		p.fail(s.Where, "a component schema is not nullable; nullability belongs to a required member")
	}
	if n := len(s.Props); n > 64 {
		p.fail(s.Where, "more than 64 members (%d)", n)
	}
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
