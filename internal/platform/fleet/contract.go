package fleet

import (
	"errors"
	"fmt"
	"unicode/utf8"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// MaxMethodBytes bounds CallOpen.method; a longer name is a protocol error (TM-D24 A4).
const MaxMethodBytes = 256

// Errors of contract binding. They name methods of our own contracts, never peer input.
var (
	ErrContract    = errors.New("fleet: contract is not valid")
	ErrNoBinding   = errors.New("fleet: no contract is bound to this component kind")
	ErrForeignImpl = errors.New("fleet: handler registered for a method outside the contract")
)

// Contract is the bound contract of one component kind (TM-D24 A1, A2): the exact full method names
// each side may open. The sets are built from generated service descriptors and are immutable.
type Contract struct {
	name        string
	toComponent map[string]struct{} // opened by the server, served by the component
	toServer    map[string]struct{} // opened by the component, served by the server
}

// NewContract builds the two direction sets from generated service descriptors. A method name is
// "/" + service full name + "/" + method name, matched byte for byte (TM-D24 A2).
func NewContract(name string, toComponent, toServer []protoreflect.ServiceDescriptor) (Contract, error) {
	if name == "" {
		return Contract{}, ErrContract
	}
	c := Contract{name: name, toComponent: map[string]struct{}{}, toServer: map[string]struct{}{}}
	for dir, svcs := range []([]protoreflect.ServiceDescriptor){toComponent, toServer} {
		set := c.toComponent
		if dir == 1 {
			set = c.toServer
		}
		for _, svc := range svcs {
			ms := svc.Methods()
			for i := 0; i < ms.Len(); i++ {
				full := "/" + string(svc.FullName()) + "/" + string(ms.Get(i).Name())
				if _, dup := c.toComponent[full]; dup {
					return Contract{}, fmt.Errorf("%w: %s is in both directions", ErrContract, full)
				}
				if _, dup := c.toServer[full]; dup {
					return Contract{}, fmt.Errorf("%w: %s is in both directions", ErrContract, full)
				}
				set[full] = struct{}{}
			}
		}
	}
	if len(c.toComponent)+len(c.toServer) == 0 {
		return Contract{}, fmt.Errorf("%w: no methods", ErrContract)
	}
	return c, nil
}

// Name is the contract's name, for logs.
func (c Contract) Name() string { return c.name }

// allows reports whether opener may open method. Exact match only: no normalisation, prefix match,
// case folding or fallback (TM-D24 A2).
func (c Contract) allows(opener Role, method string) bool {
	set := c.toServer
	if opener == RoleServer {
		set = c.toComponent
	}
	_, ok := set[method]
	return ok
}

// validMethodName is the protocol-level check on CallOpen.method (TM-D24 A4): bounded and UTF-8.
func validMethodName(m string) bool { return len(m) <= MaxMethodBytes && utf8.ValidString(m) }

// Binding is what a component kind is bound to.
type Binding struct {
	Contract Contract
	// Serve registers the server-side handlers of the contract's component to server methods on the
	// per-tunnel registrar it is given. It runs once per tunnel. The registrar refuses a method
	// outside the contract. Nil when the contract has no component to server methods.
	Serve func(id Identity, reg grpc.ServiceRegistrar)
}

// Bindings maps a component kind (from the certificate SAN) to its binding. Nothing the component
// sends selects a contract (TM-D24 A1). Build it once at start-up; it is not changed afterwards.
type Bindings map[string]Binding

// For returns the binding of id's kind.
func (b Bindings) For(id Identity) (Binding, error) {
	bd, ok := b[id.Kind]
	if !ok {
		return Binding{}, ErrNoBinding
	}
	return bd, nil
}

// registrar is the per-tunnel ServiceRegistrar (TM-D24 A3). It is not a grpc.Server: it holds only
// the contract's component to server handlers, and health, reflection, channelz and admin services
// cannot be registered on it.
type registrar struct {
	c       Contract
	opener  Role // the role whose opens this registrar serves: the peer of the Mux
	unary   map[string]unaryHandler
	streams map[string]streamHandler
	err     error
}

type unaryHandler struct {
	srv any
	h   grpc.MethodHandler
}

type streamHandler struct {
	srv any
	h   grpc.StreamHandler
}

func newRegistrar(c Contract, opener Role) *registrar {
	return &registrar{c: c, opener: opener, unary: map[string]unaryHandler{}, streams: map[string]streamHandler{}}
}

// RegisterService implements grpc.ServiceRegistrar. A method outside the contract's component to
// server set poisons the registrar; the tunnel then refuses to start.
func (r *registrar) RegisterService(sd *grpc.ServiceDesc, impl any) {
	for _, m := range sd.Methods {
		full := "/" + sd.ServiceName + "/" + m.MethodName
		if !r.c.allows(r.opener, full) {
			r.err = fmt.Errorf("%w: %s", ErrForeignImpl, full)
			return
		}
		r.unary[full] = unaryHandler{srv: impl, h: m.Handler}
	}
	for _, s := range sd.Streams {
		full := "/" + sd.ServiceName + "/" + s.StreamName
		if !r.c.allows(r.opener, full) {
			r.err = fmt.Errorf("%w: %s", ErrForeignImpl, full)
			return
		}
		r.streams[full] = streamHandler{srv: impl, h: s.Handler}
	}
}
