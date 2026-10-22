// Package apitest is the shared contract-test harness of the API (ADR-0004 A14). Every module's
// contract tests and fitness-api's route probe run their handlers through Conform, so a response
// body that does not match the schema the contract declares fails the test before it is encoded.
// It is test support: product code never imports it.
package apitest

import (
	"context"
	"encoding/json/jsontext"
	"fmt"
	"reflect"
	"sort"
	"sync"

	"github.com/skenzeriq/activediq/internal/platform/apihost"
	"github.com/skenzeriq/activediq/internal/platform/apihost/apitypes"
)

// validator is what every generated type implements: it records each violation of the schema.
type validator interface {
	Validate(at jsontext.Pointer, errs *apitypes.Errors)
}

// Violations validates a response body with the generated validators and returns one line per
// violation. A body of a type with no validator (an interface, a struct the generator did not
// emit) is itself a violation: an unvalidated response is how a handler drifts from the contract.
func Violations(resp apihost.Response) []string {
	if resp == nil {
		return []string{"the handler returned a nil response"}
	}
	body := resp.ResponseBody()
	if body == nil {
		return nil
	}
	if _, ok := body.(apihost.Stream); ok {
		return nil // a binary download has no schema
	}
	var errs apitypes.Errors
	var out []string
	walk(reflect.ValueOf(body), "", &errs, &out)
	for _, v := range errs.All() {
		out = append(out, fmt.Sprintf("%s at %q: %s", v.Code, string(v.Pointer), v.Detail))
	}
	return out
}

func walk(v reflect.Value, at string, errs *apitypes.Errors, out *[]string) {
	for v.IsValid() && (v.Kind() == reflect.Interface) {
		v = v.Elem()
	}
	if !v.IsValid() {
		return
	}
	if v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return
		}
		walk(v.Elem(), at, errs, out)
		return
	}
	if v.CanAddr() || v.Kind() == reflect.Struct {
		p := v
		if !p.CanAddr() {
			c := reflect.New(v.Type())
			c.Elem().Set(v)
			p = c.Elem()
		}
		if val, ok := p.Addr().Interface().(validator); ok {
			val.Validate(jsontext.Pointer(at), errs)
			return
		}
	}
	switch v.Kind() {
	case reflect.Slice, reflect.Array:
		for i := 0; i < v.Len(); i++ {
			walk(v.Index(i), fmt.Sprintf("%s/%d", at, i), errs, out)
		}
	case reflect.Map:
		keys := v.MapKeys()
		sort.Slice(keys, func(i, j int) bool { return keys[i].String() < keys[j].String() })
		for _, k := range keys {
			walk(v.MapIndex(k), at+"/"+k.String(), errs, out)
		}
	case reflect.Struct:
		*out = append(*out, fmt.Sprintf("%s: type %s has no generated validator", at, v.Type()))
	}
}

// Recorder collects the violations Conform finds.
type Recorder struct {
	mu    sync.Mutex
	list  []string
	types map[string][]reflect.Type
}

// Observe records the Go type of a response body a handler returned, so the type closure of A7
// can reach the Output side, which the route table does not expose.
func (r *Recorder) Observe(operationID string, t reflect.Type) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.types == nil {
		r.types = map[string][]reflect.Type{}
	}
	r.types[operationID] = append(r.types[operationID], t)
}

// Observed returns the response body types seen, by operation.
func (r *Recorder) Observed() map[string][]reflect.Type {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := map[string][]reflect.Type{}
	for k, v := range r.types {
		out[k] = append([]reflect.Type(nil), v...)
	}
	return out
}

// Add records violations of one operation.
func (r *Recorder) Add(operationID string, vs []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, v := range vs {
		r.list = append(r.list, operationID+": "+v)
	}
}

// All returns what was recorded.
func (r *Recorder) All() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.list...)
}

// Conform wraps every route so each response a handler returns is validated against its schema
// before apihost encodes it. A violation is recorded and the response is replaced by an error, so
// the request fails exactly as a client would see a server fault. Use the result in place of the
// tags passed to apihost.Build.
func Conform(rec *Recorder, tags ...apihost.TagHandlers) []apihost.TagHandlers {
	out := make([]apihost.TagHandlers, 0, len(tags))
	for _, th := range tags {
		var rows []apihost.Route
		for _, rt := range th.Routes() {
			rt := rt
			id := rt.Meta().OperationID
			rows = append(rows, apihost.NewRoute(rt.Meta(), rt.NewInput,
				func(ctx context.Context, in apihost.Input) (apihost.Response, error) {
					resp, err := rt.Call(ctx, in)
					if err != nil {
						return nil, err
					}
					if b := resp.ResponseBody(); b != nil {
						if _, stream := b.(apihost.Stream); !stream {
							rec.Observe(id, reflect.TypeOf(b))
						}
					}
					if vs := Violations(resp); len(vs) > 0 {
						rec.Add(id, vs)
						return nil, fmt.Errorf("apitest: %s response does not match its schema", id)
					}
					return resp, nil
				}))
		}
		out = append(out, apihost.NewTagHandlers(th.Tag(), rows...))
	}
	return out
}
