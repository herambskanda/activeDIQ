package apihost

import (
	"context"
	"io"
	"net/http"
	"net/url"

	"github.com/skenzeriq/activediq/internal/platform/apihost/apitypes"
)

// BodyKind says what an operation's request body is.
type BodyKind string

const (
	BodyNone       BodyKind = "none"
	BodyJSON       BodyKind = "json"
	BodyMergePatch BodyKind = "merge-patch"
	BodyBinary     BodyKind = "binary"
)

// RouteMeta is everything the contract says about one operation that the middleware chain acts on.
// The generated Bind fills it from the bundle; nothing else constructs one.
type RouteMeta struct {
	OperationID string
	Tag         string
	Method      string // upper case
	Path        string // relative to /api/v1, in ServeMux wildcard syntax
	Permission  string // an EP-6 permission ID, "authenticated" or "anonymous" (rule 3)
	Anonymous   string // the policy.anonymous row, for anonymous operations
	Scope       string // "tenant" or "platform"
	Stability   string // "preview" or "stable"
	Deprecated  bool
	Sunset      string
	Class       string // rate class (rule 10)
	MaxBody     int64  // maxBodyBytes
	Body        BodyKind
	MediaType   string // the request media type, empty without a body
	Secret      bool   // the Input type closure reaches SecretInput (rule 6)
}

// Request is what apihost hands a route after the middleware chain has run: the parts of the HTTP
// request a handler's Input may contain. A handler never sees *http.Request.
type Request struct {
	PathValue func(name string) string
	Query     url.Values
	Header    http.Header
	Upload    Upload // set for a binary request body
}

// Upload is a binary request body, read through a cap apihost enforces. It is never secret-bearing.
type Upload struct{ io.Reader }

// Stream is a binary response body (an export download).
type Stream struct {
	io.Reader
	ContentType string
	Filename    string
}

// Input is the generated, typed input of one operation. apihost drives it in rule 6 order:
// BindRequest for path, query and headers, then secretjson.Decode into BodyTarget, then Validate,
// then the handler, then DestroySecrets.
type Input interface {
	// BindRequest parses path, query and header parameters into the Input, recording violations.
	BindRequest(r *Request, errs *apitypes.Errors)
	// BodyTarget is the pointer to decode the JSON body into, or nil when there is none.
	BodyTarget() any
	// Validate checks every declared bound of the parameters and the decoded body.
	Validate(errs *apitypes.Errors)
	// DestroySecrets destroys every Secret in the Input.
	DestroySecrets()
}

// Response is a successful (non-problem) response a handler returns. Errors, 4xx and 5xx, are
// returned as the error value: an apitypes problem constructor or a plain error.
type Response interface {
	StatusCode() int
	ResponseBody() any // nil for no body; apihost encodes it with json v2, or streams a Stream
	ResponseHeaders() map[string]string
}

// Route is one operation's row: its metadata plus the generated adapter that builds its Input
// and calls the handler. Its fields are unexported so only NewRoute, called from generated code,
// can make one (ADR-0004 A6).
type Route struct {
	meta     RouteMeta
	newInput func() Input
	call     func(ctx context.Context, in Input) (Response, error)
}

// NewRoute builds a route row. Only generated Bind functions call it.
func NewRoute(meta RouteMeta, newInput func() Input, call func(ctx context.Context, in Input) (Response, error)) Route {
	return Route{meta: meta, newInput: newInput, call: call}
}

// Meta returns the operation metadata.
func (r Route) Meta() RouteMeta { return r.meta }

// NewInput returns a fresh Input for one request.
func (r Route) NewInput() Input { return r.newInput() }

// Call invokes the handler with an Input from NewInput.
func (r Route) Call(ctx context.Context, in Input) (Response, error) { return r.call(ctx, in) }

// TagHandlers is one tag's contribution: every route of the tag, bound to a handler. A module
// passes it to Registrar.API (ADR-0003 EP-2).
type TagHandlers struct {
	tag    string
	routes []Route
}

// NewTagHandlers groups routes under their tag. Only generated Bind functions call it.
func NewTagHandlers(tag string, routes ...Route) TagHandlers {
	return TagHandlers{tag: tag, routes: routes}
}

// Tag is the OpenAPI tag, equal to the module ID or "platform.<pkg>".
func (t TagHandlers) Tag() string { return t.tag }

// Routes returns the tag's route rows.
func (t TagHandlers) Routes() []Route { return append([]Route(nil), t.routes...) }
