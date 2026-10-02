package main

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var (
	permissionRe = regexp.MustCompile(`^[a-z][A-Za-z0-9_.:*-]*$`)
	pathParamRe  = regexp.MustCompile(`\{([A-Za-z0-9]+)\}`)
	classes      = []string{"read", "write", "bulk", "auth", "reveal", "anonymous"}
	mediaJSON    = "application/json"
	mediaPatch   = "application/merge-patch+json"
	mediaProblem = "application/problem+json"
	binaryMedia  = []string{"application/octet-stream", "text/csv"}
)

const defaultMaxBody = 1 << 20

func (m *Model) parseOps(p *parser, doc Doc) {
	paths, _ := doc["paths"].(Doc)
	names := make([]string, 0, len(paths))
	for n := range paths {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, path := range names {
		item := paths[path].(Doc)
		for _, method := range httpMethods {
			raw, ok := item[method].(Doc)
			if !ok {
				continue
			}
			where := strings.ToUpper(method) + " " + path
			op := &Operation{Method: strings.ToUpper(method), Path: path}
			m.parseOp(p, op, raw, where)
			m.Ops = append(m.Ops, op)
		}
	}
	sort.Slice(m.Ops, func(i, j int) bool { return m.Ops[i].ID < m.Ops[j].ID })
}

func (m *Model) parseOp(p *parser, op *Operation, raw Doc, where string) {
	allowed := []string{"tags", "operationId", "summary", "description", "deprecated", "parameters", "requestBody", "responses", "security",
		"x-permission", "x-activediq-scope", "x-activediq-stability", "x-activediq-sunset", "x-activediq-limits", "x-activediq-anonymous", "x-activediq-parity"}
	for k := range raw {
		if !contains(allowed, k) {
			if strings.HasPrefix(k, "x-") {
				p.fail(where, "extension %q is not one of the rule 3 list", k)
			} else {
				p.fail(where, "operation key %q is outside the dialect", k)
			}
		}
	}
	op.ID, _ = raw["operationId"].(string)
	op.Summary, _ = raw["summary"].(string)
	if tags, _ := raw["tags"].([]any); len(tags) == 1 {
		op.Tag, _ = tags[0].(string)
	}
	op.Deprecated, _ = raw["deprecated"].(bool)

	// Rule 3 extensions.
	perm, _ := raw["x-permission"].(string)
	if !permissionRe.MatchString(perm) {
		p.fail(where, "x-permission is required, exactly one, and is a permission ID, \"authenticated\" or \"anonymous\" (found %v)", raw["x-permission"])
	}
	op.Permission = perm
	op.Scope = "tenant"
	if v, ok := raw["x-activediq-scope"]; ok {
		if v != "platform" {
			p.fail(where, "x-activediq-scope may only be \"platform\"")
		} else {
			op.Scope = "platform"
		}
	}
	op.Stability, _ = raw["x-activediq-stability"].(string)
	if op.Stability != "preview" && op.Stability != "stable" {
		p.fail(where, "x-activediq-stability is required: preview or stable")
	}
	if v, ok := raw["x-activediq-sunset"].(string); ok {
		op.Sunset = v
	}
	if op.Deprecated != (op.Sunset != "") {
		p.fail(where, "deprecated: true and x-activediq-sunset go together")
	}
	if v, ok := raw["x-activediq-anonymous"].(string); ok {
		op.Anonymous = v
	}
	if (perm == "anonymous") != (op.Anonymous != "") {
		p.fail(where, "x-permission: anonymous and x-activediq-anonymous go together")
	}
	op.Class = "read"
	if op.Method != "GET" && op.Method != "HEAD" {
		op.Class = "write"
	}
	op.MaxBody = defaultMaxBody
	if lim, ok := raw["x-activediq-limits"].(Doc); ok {
		for k := range lim {
			if k != "class" && k != "maxBodyBytes" {
				p.fail(where, "x-activediq-limits key %q is not allowed (class, maxBodyBytes)", k)
			}
		}
		if c, ok := lim["class"].(string); ok {
			if !contains(classes, c) {
				p.fail(where, "rate class %q is unknown (%s)", c, strings.Join(classes, ", "))
			}
			op.Class = c
		}
		if v, ok := lim["maxBodyBytes"]; ok {
			n, isInt := asInt(v)
			if !isInt || n <= 0 {
				p.fail(where, "maxBodyBytes must be a positive integer")
			}
			op.MaxBody = n
		}
	}
	if v, ok := raw["x-activediq-parity"]; ok {
		if l, isList := v.([]any); !isList {
			p.fail(where, "x-activediq-parity is a list of feature IDs")
		} else {
			for _, e := range l {
				if _, isStr := e.(string); !isStr {
					p.fail(where, "x-activediq-parity is a list of feature IDs")
				}
			}
		}
	}

	// Parameters.
	seen := map[string]bool{}
	pathParams := map[string]bool{}
	for i, rp := range anyList(raw["parameters"]) {
		pm := p.parseParam(rp, fmt.Sprintf("%s.parameters[%d]", where, i), m)
		if pm == nil {
			continue
		}
		key := pm.In + ":" + pm.Name
		if seen[key] {
			p.fail(where, "parameter %s %q is declared twice", pm.In, pm.Name)
		}
		seen[key] = true
		if pm.In == "path" {
			pathParams[pm.Name] = true
		}
		op.Params = append(op.Params, pm)
	}
	tmpl := map[string]bool{}
	for _, mm := range pathParamRe.FindAllStringSubmatch(op.Path, -1) {
		tmpl[mm[1]] = true
		if !pathParams[mm[1]] {
			p.fail(where, "path parameter {%s} is not declared", mm[1])
		}
	}
	for n := range pathParams {
		if !tmpl[n] {
			p.fail(where, "path parameter %q is not in the path", n)
		}
	}

	// Request body.
	if rb, ok := raw["requestBody"].(Doc); ok {
		op.Body = p.parseBody(rb, where+".requestBody")
	} else if _, has := raw["requestBody"]; has {
		p.fail(where, "requestBody must be an object (a requestBody $ref is not supported)")
	}
	if op.Method == "PATCH" {
		if op.Body == nil || op.Body.Media != mediaPatch {
			p.fail(where, "a PATCH body is %s (RFC 7396)", mediaPatch)
		}
	} else if op.Body != nil && op.Body.Media == mediaPatch {
		p.fail(where, "%s is for PATCH only", mediaPatch)
	}
	if (op.Method == "GET" || op.Method == "HEAD" || op.Method == "DELETE") && op.Body != nil {
		p.fail(where, "%s carries no request body", op.Method)
	}

	// Responses.
	resps, _ := raw["responses"].(Doc)
	codes := make([]string, 0, len(resps))
	for c := range resps {
		codes = append(codes, c)
	}
	sort.Strings(codes)
	has2xx := false
	for _, code := range codes {
		status, err := strconv.Atoi(code)
		if err != nil || status < 200 || status > 599 {
			p.fail(where, "response key %q is not an HTTP status code", code)
			continue
		}
		r := p.parseResp(m, resps[code], status, fmt.Sprintf("%s.responses.%s", where, code))
		if r == nil {
			continue
		}
		if status < 400 {
			has2xx = true
		}
		op.Responses = append(op.Responses, r)
	}
	if !has2xx {
		p.fail(where, "an operation declares a success response")
	}
	if len(op.Responses) == 0 {
		return
	}
}

func anyList(v any) []any { l, _ := v.([]any); return l }

func (p *parser) parseBody(rb Doc, where string) *Body {
	for k := range rb {
		if !contains([]string{"required", "content", "description"}, k) {
			p.fail(where, "requestBody key %q is outside the dialect", k)
		}
	}
	b := &Body{}
	b.Required, _ = rb["required"].(bool)
	content, _ := rb["content"].(Doc)
	if len(content) != 1 {
		p.fail(where, "a request body has exactly one media type")
		return nil
	}
	for media, v := range content {
		b.Media = media
		md, _ := v.(Doc)
		switch {
		case media == mediaJSON || media == mediaPatch:
			s := p.parseSchema(md["schema"], where+".content."+media+".schema", false)
			if s.Ref == "" {
				p.fail(where, "a JSON body schema is a $ref to a named object or union")
			}
			b.Schema = s
		case contains(binaryMedia, media):
			b.Binary = true
			p.checkBinarySchema(md, where)
		default:
			p.fail(where, "request media type %q is not allowed (%s, %s, %s)", media, mediaJSON, mediaPatch, strings.Join(binaryMedia, ", "))
		}
	}
	return b
}

func (p *parser) checkBinarySchema(md Doc, where string) {
	sc, _ := md["schema"].(Doc)
	if sc == nil || sc["type"] != "string" || sc["format"] != "binary" || len(sc) != 2 {
		p.fail(where, "a binary body schema is exactly {type: string, format: binary}")
	}
}

func (p *parser) parseResp(m *Model, raw any, status int, where string) *Resp {
	rd, _ := raw.(Doc)
	if rd == nil {
		p.fail(where, "a response must be an object")
		return nil
	}
	r := &Resp{Status: status, Problem: status >= 400}
	if ref, ok := rd["$ref"].(string); ok {
		name, found := strings.CutPrefix(ref, "#/components/responses/")
		isProblem := false
		for _, pr := range m.Problems {
			if pr.Name == name {
				isProblem = true
			}
		}
		if !found || !isProblem || status < 400 {
			p.fail(where, "only an error response of the problem catalogue may be a $ref (found %q at status %d)", ref, status)
		}
		return r
	}
	for k := range rd {
		if !contains([]string{"description", "headers", "content"}, k) {
			p.fail(where, "response key %q is outside the dialect", k)
		}
	}
	if status >= 400 {
		p.fail(where, "an error response is a $ref to the problem catalogue (shared/problems.yaml)")
		return r
	}
	headers, _ := rd["headers"].(Doc)
	hn := make([]string, 0, len(headers))
	for n := range headers {
		hn = append(hn, n)
	}
	sort.Strings(hn)
	for _, n := range hn {
		hd, _ := headers[n].(Doc)
		sc, _ := hd["schema"].(Doc)
		if sc == nil || sc["type"] != "string" {
			p.fail(where, "response header %q is a string", n)
		}
		req, _ := hd["required"].(bool)
		r.Headers = append(r.Headers, RespHeader{Name: n, Required: req})
	}
	content, _ := rd["content"].(Doc)
	if len(content) > 1 {
		p.fail(where, "a response has at most one media type")
	}
	for media, v := range content {
		r.Media = media
		md, _ := v.(Doc)
		switch {
		case media == mediaJSON:
			s := p.parseSchema(md["schema"], where+".content."+media+".schema", false)
			if s.Ref == "" {
				p.fail(where, "a JSON response schema is a $ref to a named schema")
			}
			r.Schema = s
		case contains(binaryMedia, media):
			r.Binary = true
			p.checkBinarySchema(md, where)
		default:
			p.fail(where, "response media type %q is not allowed", media)
		}
	}
	return r
}
