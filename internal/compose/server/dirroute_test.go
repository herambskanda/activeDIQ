package server

import (
	"context"

	"github.com/skenzeriq/activediq/internal/platform/apihost"
	"github.com/skenzeriq/activediq/internal/platform/apihost/apitypes"
	"github.com/skenzeriq/activediq/internal/platform/authn/tenantref"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// usersRoute stands in for the directory module's GET /directory/users in the sign-in tests. Those tests
// prove the session, its grant of directory.read and the tenant the request runs under; the module's own
// handler is proved in internal/modules/directory (compose/server names no module, ADR-0013 decision 4).
// It answers one user and records the tenant the authenticated principal carried.
type usersRoute struct{ tid tenant.ID }

type usersInput struct{}

func (usersInput) BindRequest(*apihost.Request, *apitypes.Errors) {}
func (usersInput) BodyTarget() any                                { return nil }
func (usersInput) Validate(*apitypes.Errors)                      {}
func (usersInput) DestroySecrets()                                {}

type usersOutput struct{}

func (usersOutput) StatusCode() int                    { return 200 }
func (usersOutput) ResponseHeaders() map[string]string { return nil }
func (usersOutput) ResponseBody() any {
	return map[string]any{"users": []map[string]any{{
		"objectGuid": "aaaaaaaa-0000-4000-8000-00000000000a", "displayName": "Ada Bianchi", "samAccountName": "ada.bianchi", "enabled": true,
	}}}
}

func (u *usersRoute) Bind() apihost.TagHandlers {
	return directoryTag(func(ctx context.Context, _ apihost.Input) (apihost.Response, error) {
		p, ok := apihost.PrincipalFrom(ctx)
		if !ok {
			return nil, apitypes.Unauthenticated("")
		}
		tid, err := tenantref.TenantFromText(p.Tenant)
		if err != nil {
			return nil, apitypes.Unauthenticated("")
		}
		u.tid = tid
		return usersOutput{}, nil
	})
}

// panicRoute is the same route whose handler must never run: the caller lacks directory.read.
type panicRoute struct{}

func (*panicRoute) Bind() apihost.TagHandlers {
	return directoryTag(func(context.Context, apihost.Input) (apihost.Response, error) {
		panic("handler ran for a caller without directory.read")
	})
}

// searchInput is the body of the stand-in for POST /directory/search; nothing reads it.
type searchInput struct{ body map[string]any }

func (s *searchInput) BindRequest(*apihost.Request, *apitypes.Errors) {}
func (s *searchInput) BodyTarget() any                                { return &s.body }
func (s *searchInput) Validate(*apitypes.Errors)                      {}
func (s *searchInput) DestroySecrets()                                {}

// directoryTag is the directory tag as the contract declares it (both operations), with users as the
// handler of GET /directory/users; universal search is not the subject of these tests and answers 404.
func directoryTag(users func(context.Context, apihost.Input) (apihost.Response, error)) apihost.TagHandlers {
	explorer := func(id, path string) apihost.Route {
		return apihost.NewRoute(apihost.RouteMeta{
			OperationID: id, Tag: "directory", Method: "GET", Path: path,
			Permission: "directory.read", Scope: "tenant", Stability: "preview",
			Class: "read", Body: apihost.BodyNone,
		},
			func() apihost.Input { return usersInput{} },
			func(context.Context, apihost.Input) (apihost.Response, error) { return nil, apitypes.NotFound("") })
	}
	return apihost.NewTagHandlers("directory",
		explorer("getExplorerNode", "/directory/explorer/nodes/{objectGuid}"),
		explorer("listExplorerChildren", "/directory/explorer/nodes/{objectGuid}/children"),
		explorer("listExplorerRoots", "/directory/explorer/roots"),
		apihost.NewRoute(apihost.RouteMeta{
			OperationID: "searchDirectory", Tag: "directory", Method: "POST", Path: "/directory/search",
			Permission: "directory.read", Scope: "tenant", Stability: "preview",
			Class: "read", MaxBody: 4096, Body: apihost.BodyJSON, MediaType: "application/json",
		},
			func() apihost.Input { return &searchInput{} },
			func(context.Context, apihost.Input) (apihost.Response, error) { return nil, apitypes.NotFound("") }),
		apihost.NewRoute(apihost.RouteMeta{
			OperationID: "searchDirectoryUsers", Tag: "directory", Method: "GET", Path: "/directory/users",
			Permission: "directory.read", Scope: "tenant", Stability: "preview",
			Class: "read", Body: apihost.BodyNone,
		},
			func() apihost.Input { return usersInput{} }, users))
}
