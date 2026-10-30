package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/skenzeriq/activediq/internal/directory/connection"
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
)

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
type UserSearch struct {
	conns ConnectionSource
	src   ConnectorSource
}

// NewUserSearch returns the search client. Both arguments are required.
func NewUserSearch(conns ConnectionSource, src ConnectorSource) (*UserSearch, error) {
	switch {
	case conns == nil:
		return nil, errors.New("client: user search needs a connection source")
	case src == nil:
		return nil, ErrNoSearchSource
	}
	return &UserSearch{conns: conns, src: src}, nil
}

// Users answers the users of connection id whose displayName, sAMAccountName or userPrincipalName
// contains text, sorted by display name, sAMAccountName, then objectGUID, at most limit of them.
// The root is the forest root naming context (the connection's directory identity).
func (s *UserSearch) Users(ctx context.Context, tid tenant.ID, id connection.ID, text string, limit int) (UserSearchResult, error) {
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
	root := ident.GetAdForest().GetForestRootNcGuid()
	cc, err := s.src.Connector(ctx, string(id))
	if err != nil {
		return UserSearchResult{}, err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	st, err := cc.ScopedSearch(ctx, &connectorv1.ScopedSearchRequest{
		Connection: &connectorv1.ConnectionRef{ConnectionId: string(id), DirectoryIdentity: ident},
		Roots:      []*connectorv1.SearchRoot{{Guid: root, NcGuid: root}},
		Depth:      connectorv1.SearchDepth_SEARCH_DEPTH_SUBTREE,
		Filter:     userFilter(text),
		Attributes: searchAttrs,
	})
	if err != nil {
		return UserSearchResult{}, FromStatus(err)
	}
	var (
		res       UserSearchResult
		completed bool
	)
read:
	for {
		m, err := st.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return UserSearchResult{}, FromStatus(err)
		}
		if completed {
			return UserSearchResult{}, ErrSearchProtocol
		}
		switch ev := m.GetEvent().(type) {
		case *connectorv1.ScopedSearchResponse_Batch:
			for _, e := range ev.Batch.GetEntries() {
				u, err := foundUser(e)
				if err != nil {
					return UserSearchResult{}, err
				}
				res.Users = append(res.Users, u)
				if len(res.Users) > MaxSearchMatches {
					res.Truncated = true
					completed = true
					break read // cancel: the deferred cancel stops the stream
				}
			}
		case *connectorv1.ScopedSearchResponse_Completed:
			completed = true
		case *connectorv1.ScopedSearchResponse_RootCompleted:
		default:
			return UserSearchResult{}, ErrSearchProtocol
		}
	}
	if !completed {
		return UserSearchResult{}, ErrSearchIncomplete
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
