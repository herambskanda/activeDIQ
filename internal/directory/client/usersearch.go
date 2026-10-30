package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"sort"
	"strings"

	"github.com/skenzeriq/activediq/internal/directory/connection"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// Errors of the user search. None carries a directory value or a connector message.
var (
	ErrNoSearchSource    = errors.New("client: no connector source wired for search")
	ErrSearchConnection  = errors.New("client: connection is not an active AD connection with a verified directory")
	ErrSearchProtocol    = errors.New("client: search stream violates the contract")
	ErrSearchIncomplete  = errors.New("client: search ended without a completion marker")
	ErrSearchTextInvalid = errors.New("client: search text is empty or not valid text")
	// ErrSearchScope: the ancestry of a result could not be read, so the caller's read scope could not
	// be applied. The search fails; it never answers an unchecked result.
	ErrSearchScope = errors.New("client: search could not apply the read scope")
)

// maxSearchRoots is how many roots one ScopedSearch request carries (the connector refuses more).
const maxSearchRoots = 64

// maxAncestryReads bounds the container reads one search makes to find its results' parent chains.
// Containers are read once per search however many results share them. Past the budget a chain is
// reported incomplete, and an incomplete chain is not admitted (fail closed).
const maxAncestryReads = 2000

// MaxSearchMatches bounds what one user search reads from the connector. The text is a contains
// match, so a one-letter query on a large domain could match most of it; past this many matches the
// stream is cancelled and the (still sorted) matches read so far are answered with Truncated set.
const MaxSearchMatches = 1000

// searchAttrs is the closed attribute list a user search asks for: exactly what the API returns.
var searchAttrs = []string{"displayName", "sAMAccountName", "userPrincipalName", "userAccountControl"}

// uacAccountDisable is ACCOUNTDISABLE in userAccountControl.
const uacAccountDisable = 0x2

// FoundUser is one search result: only the fields the API exposes.
type FoundUser struct {
	ObjectGUID        string
	DisplayName       string
	SAMAccountName    string
	UserPrincipalName string
	Enabled           bool
	// Parent is the objectGUID of the parent container, empty for the head of a naming context.
	Parent string
}

// UserSearchResult is the answer of Users.
type UserSearchResult struct {
	Users []FoundUser
	// Truncated: more than MaxSearchMatches users matched; the answer is the sorted head of what was read.
	Truncated bool
}

// UserSearch searches the users of one AD connection through the connector's ScopedSearch RPC. The
// search text becomes a value in a typed filter tree (substring nodes), never filter syntax: the
// connector validates the tree against its schema and renders the text with RFC 4515 escaping.
//
// The search is trimmed to the caller's authz.ReadScope before anything is answered (m2-plan decision
// 4, LF-39): the include roots of the scope are the roots of the directory query, so the directory
// does not return objects outside every include; each result's live parent chain is then read and
// checked with ReadScope.Admits, which applies excludes and the token layer. The match cap and the
// limit count admitted results only.
type UserSearch struct {
	conns ConnectionSource
	src   ConnectorSource
	reads Reads
}

// NewUserSearch returns the search client. All arguments are required: reads supplies the parent
// chains the scope is checked against, so there is no unscoped search.
func NewUserSearch(conns ConnectionSource, src ConnectorSource, reads Reads) (*UserSearch, error) {
	switch {
	case conns == nil:
		return nil, errors.New("client: user search needs a connection source")
	case src == nil:
		return nil, ErrNoSearchSource
	case reads == nil:
		return nil, ErrNoReads
	}
	return &UserSearch{conns: conns, src: src, reads: reads}, nil
}

// Users answers the users of connection id whose displayName, sAMAccountName or userPrincipalName
// contains text and that scope admits, sorted by display name, sAMAccountName, then objectGUID, at
// most limit of them. A scope that reaches nothing in the connection answers nothing without asking
// the directory. The roots of the query are the scope's include roots in this connection; the zero
// ReadScope grants nothing.
func (s *UserSearch) Users(ctx context.Context, tid tenant.ID, id connection.ID, text string, limit int, scope authz.ReadScope) (UserSearchResult, error) {
	if strings.TrimSpace(text) == "" || strings.ContainsRune(text, 0) {
		return UserSearchResult{}, ErrSearchTextInvalid
	}
	conn, err := s.conns.Get(ctx, tid, id)
	if err != nil || conn.ID != id || conn.RetiredAt != nil || conn.Kind != connection.KindADForest || conn.State != connection.StateActive {
		return UserSearchResult{}, ErrSearchConnection
	}
	ident := directoryOf(conn)
	if ident == nil {
		return UserSearchResult{}, ErrSearchConnection
	}
	connID, err := authz.ParseObjectID(string(id))
	if err != nil {
		return UserSearchResult{}, ErrSearchConnection
	}
	scoped := scope.SearchRoots(connID)
	if len(scoped) == 0 {
		return UserSearchResult{}, nil // the scope reaches nothing here: nothing to ask, nothing to count
	}
	forestRoot := ident.GetAdForest().GetForestRootNcGuid()
	cc, err := s.src.Connector(ctx, string(id))
	if err != nil {
		return UserSearchResult{}, err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	chains := &chainResolver{ctx: authority.WithTenant(ctx, tid.String()), reads: s.reads, conn: string(id), connID: connID,
		parents: map[string]parentRead{}, budget: maxAncestryReads}
	seen := map[string]bool{}
	var res UserSearchResult
	for _, depth := range []struct {
		kind  authz.TermKind
		depth connectorv1.SearchDepth
	}{{authz.TermSubtree, connectorv1.SearchDepth_SEARCH_DEPTH_SUBTREE}, {authz.TermOneLevel, connectorv1.SearchDepth_SEARCH_DEPTH_ONE_LEVEL}} {
		var roots []*connectorv1.SearchRoot
		for _, r := range scoped {
			if r.Kind == depth.kind {
				// The NC of an OU root is not in a scope term; the forest root names the connection's
				// directory, which is what the connector checks (the server asks the bound DC by GUID).
				roots = append(roots, &connectorv1.SearchRoot{Guid: wireGUID(r.Root), NcGuid: forestRoot})
			}
		}
		for len(roots) > 0 {
			n := min(len(roots), maxSearchRoots)
			done, err := s.searchRoots(ctx, cc, id, ident, roots[:n], depth.depth, text, scope, connID, chains, seen, &res)
			if err != nil {
				return UserSearchResult{}, err
			}
			if done { // the cap was reached
				break
			}
			roots = roots[n:]
		}
		if res.Truncated {
			break
		}
	}
	sort.Slice(res.Users, func(i, j int) bool {
		a, b := res.Users[i], res.Users[j]
		if x, y := strings.ToLower(a.DisplayName), strings.ToLower(b.DisplayName); x != y {
			return x < y
		}
		if x, y := strings.ToLower(a.SAMAccountName), strings.ToLower(b.SAMAccountName); x != y {
			return x < y
		}
		return a.ObjectGUID < b.ObjectGUID
	})
	if limit > 0 && len(res.Users) > limit {
		res.Users = res.Users[:limit]
	}
	return res, nil
}

// searchRoots runs one ScopedSearch over roots and appends the admitted users to res. It reports
// done when the match cap was reached.
func (s *UserSearch) searchRoots(ctx context.Context, cc connectorv1.ConnectorClient, id connection.ID, ident *connectorv1.DirectoryIdentity,
	roots []*connectorv1.SearchRoot, depth connectorv1.SearchDepth, text string, scope authz.ReadScope, connID authz.ObjectID,
	chains *chainResolver, seen map[string]bool, res *UserSearchResult) (done bool, err error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel() // stops the stream when the cap is reached
	st, err := cc.ScopedSearch(ctx, &connectorv1.ScopedSearchRequest{
		Connection: &connectorv1.ConnectionRef{ConnectionId: string(id), DirectoryIdentity: ident},
		Roots:      roots,
		Depth:      depth,
		Filter:     userFilter(text),
		Attributes: searchAttrs,
	})
	if err != nil {
		return false, FromStatus(err)
	}
	completed := false
	for {
		m, err := st.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return false, FromStatus(err)
		}
		if completed {
			return false, ErrSearchProtocol
		}
		switch ev := m.GetEvent().(type) {
		case *connectorv1.ScopedSearchResponse_Batch:
			for _, e := range ev.Batch.GetEntries() {
				u, err := foundUser(e)
				if err != nil {
					return false, err
				}
				if seen[u.ObjectGUID] {
					continue // reached through two roots
				}
				seen[u.ObjectGUID] = true
				view, err := chains.view(u)
				if err != nil {
					return false, err
				}
				if !scope.Admits(view) {
					continue
				}
				res.Users = append(res.Users, u)
				if len(res.Users) > MaxSearchMatches {
					res.Truncated = true
					return true, nil
				}
			}
		case *connectorv1.ScopedSearchResponse_Completed:
			completed = true
		case *connectorv1.ScopedSearchResponse_RootCompleted:
		default:
			return false, ErrSearchProtocol
		}
	}
	if !completed {
		return false, ErrSearchIncomplete
	}
	return false, nil
}

// parentRead is what one container read answered: whether it exists and its parent.
type parentRead struct {
	exists bool
	parent string
}

// chainResolver reads the parent chains of search results, once per container per search. The chain
// is read live from the directory, the same facts Authorize uses for a single object
// (ConnectorFacts); nothing comes from the inventory, whose ancestry may be stale.
type chainResolver struct {
	ctx     context.Context
	reads   Reads
	conn    string
	connID  authz.ObjectID
	parents map[string]parentRead
	budget  int
}

// view builds the ObjectView of a found user. The chain is nearest parent first up to the head of the
// naming context. Complete is false for a loop, a container that vanished, a chain deeper than
// maxAncestry or an exhausted read budget; the scope then admits nothing for the user.
func (c *chainResolver) view(u FoundUser) (authz.ObjectView, error) {
	oid, err := authz.ParseObjectID(u.ObjectGUID)
	if err != nil {
		return authz.ObjectView{}, ErrSearchProtocol
	}
	v := authz.ObjectView{Connection: c.connID, ID: oid}
	visited := map[string]bool{u.ObjectGUID: true}
	for cur := u.Parent; cur != ""; {
		if visited[cur] || len(v.Ancestors) >= maxAncestry {
			return v, nil
		}
		visited[cur] = true
		aid, err := authz.ParseObjectID(cur)
		if err != nil {
			return v, nil
		}
		v.Ancestors = append(v.Ancestors, aid)
		p, ok, err := c.parentOf(cur)
		if err != nil {
			return authz.ObjectView{}, err
		}
		if !ok || !p.exists {
			return v, nil
		}
		cur = p.parent
	}
	v.Complete = true
	return v, nil
}

// parentOf reads container guid (memoised). ok is false when the read budget is spent.
func (c *chainResolver) parentOf(guid string) (parentRead, bool, error) {
	if p, hit := c.parents[guid]; hit {
		return p, true, nil
	}
	if c.budget <= 0 {
		return parentRead{}, false, nil
	}
	c.budget--
	o, err := c.reads.Object(c.ctx, nil, authority.TargetRef{Connection: c.conn, GUID: guid, Class: "container"}, guid, false)
	if err != nil {
		return parentRead{}, false, fmt.Errorf("%w: reading a container", ErrSearchScope)
	}
	p := parentRead{exists: o.Exists, parent: o.Parent}
	c.parents[guid] = p
	return p, true, nil
}

// wireGUID is an ObjectID (AD octet order) as the wire Guid, which is RFC 4122 order (the byte order
// of the canonical text): the first three fields swap.
func wireGUID(id authz.ObjectID) *connectorv1.Guid {
	b := slices.Clone(id[:])
	slices.Reverse(b[0:4])
	slices.Reverse(b[4:6])
	slices.Reverse(b[6:8])
	return &connectorv1.Guid{Value: b}
}

// userFilter is (&(objectClass=user)(!(objectClass=computer))(|(displayName=*t*)(sAMAccountName=*t*)(userPrincipalName=*t*))).
// The text is the single value of each substring node.
func userFilter(text string) *connectorv1.Filter {
	eq := func(attr, v string) *connectorv1.Filter {
		return &connectorv1.Filter{Node: &connectorv1.Filter_Equal{Equal: &connectorv1.Comparison{Attribute: attr,
			Value: &connectorv1.FilterValue{Value: &connectorv1.FilterValue_Text{Text: v}}}}}
	}
	sub := func(attr string) *connectorv1.Filter {
		return &connectorv1.Filter{Node: &connectorv1.Filter_Substring{Substring: &connectorv1.Substring{Attribute: attr, Any: []string{text}}}}
	}
	list := func(k ...*connectorv1.Filter) *connectorv1.FilterList { return &connectorv1.FilterList{Children: k} }
	return &connectorv1.Filter{Node: &connectorv1.Filter_And{And: list(
		eq("objectClass", "user"),
		&connectorv1.Filter{Node: &connectorv1.Filter_Not{Not: eq("objectClass", "computer")}},
		&connectorv1.Filter{Node: &connectorv1.Filter_Or{Or: list(sub("displayName"), sub("sAMAccountName"), sub("userPrincipalName"))}},
	)}}
}

func foundUser(e *connectorv1.DirectoryEntry) (FoundUser, error) {
	g := e.GetObjectGuid().GetValue()
	if len(g) != 16 {
		return FoundUser{}, ErrSearchProtocol
	}
	u := FoundUser{ObjectGUID: fmt.Sprintf("%x-%x-%x-%x-%x", g[0:4], g[4:6], g[6:8], g[8:10], g[10:16]), Enabled: true}
	if p := e.GetParentGuid().GetValue(); len(p) != 0 {
		if len(p) != 16 {
			return FoundUser{}, ErrSearchProtocol
		}
		u.Parent = fmt.Sprintf("%x-%x-%x-%x-%x", p[0:4], p[4:6], p[6:8], p[8:10], p[10:16])
	}
	for _, a := range e.GetAttributes() {
		if len(a.GetValues()) == 0 {
			continue
		}
		v := a.GetValues()[0]
		switch strings.ToLower(a.GetName()) {
		case "displayname":
			u.DisplayName = v.GetText()
		case "samaccountname":
			u.SAMAccountName = v.GetText()
		case "userprincipalname":
			u.UserPrincipalName = v.GetText()
		case "useraccountcontrol":
			u.Enabled = v.GetInt32Value()&uacAccountDisable == 0
		}
	}
	return u, nil
}
