// Package policyjson converts api/openapi/policy.yaml to the JSON the shipped server embeds
// (apihost.ParsePolicy reads JSON), so the product binary never links a YAML parser (ADR-0004,
// F3 denylist). It is tools-only: gen-api writes the result and fitness-api A4 passes the same
// bytes to apihost.ParsePolicy.
package policyjson

import (
	"bytes"
	"encoding/json"
	"fmt"

	"go.yaml.in/yaml/v3"
)

// FromYAML converts policy.yaml to indented JSON with a trailing newline. Duplicate keys, aliases
// and non-string keys fail rather than convert silently.
func FromYAML(b []byte) ([]byte, error) {
	var v any
	if err := yaml.Unmarshal(b, &v); err != nil {
		return nil, fmt.Errorf("policy.yaml does not parse: %w", err)
	}
	if v == nil {
		v = map[string]any{}
	}
	if _, err := check(v); err != nil {
		return nil, fmt.Errorf("policy.yaml: %w", err)
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func check(v any) (any, error) {
	switch x := v.(type) {
	case map[string]any:
		for _, e := range x {
			if _, err := check(e); err != nil {
				return nil, err
			}
		}
	case map[any]any:
		return nil, fmt.Errorf("a mapping key is not a string (quote it)")
	case []any:
		for _, e := range x {
			if _, err := check(e); err != nil {
				return nil, err
			}
		}
	}
	return v, nil
}
