package main

import (
	"go/ast"
	"go/token"
	"strconv"
	"strings"
)

const (
	fleetsqlDir = "internal/platform/fleet/fleetsql"
	gatewayDir  = "internal/platform/fleet/gateway"
	dialDir     = "internal/platform/fleet/dial"
	composeDir  = "internal/compose"
	fleetDir    = "internal/platform/fleet"
)

// signAllowed are the functions of fleetsql that may call x509.CreateCertificate: tenant CA creation,
// the ClientAuth leaf issuer, and the server CA's own two entry points (ADR-0008 item 7).
var signAllowed = map[string]bool{"createCA": true, "issue": true, "createServerCA": true, "SignServerLeaf": true}

// serverSignerCallers may call the unexported server CA signer.
var serverSignerCallers = map[string]bool{"createServerCA": true, "SignServerLeaf": true}

// forbiddenLeafParam are type spellings SignServerLeaf may not take: the leaf key is generated inside.
var forbiddenLeafParam = []string{"PublicKey", "PrivateKey", "Signer", "CertificateRequest", "[]byte"}

type state struct{ signLeaf, serverSigner, pinnedRoots bool }

// checkAll runs FCS-1..4 and FCS-6 on the parsed tree. schemaPresent says that a fleet_server_ca
// migration exists; with it, the code that signs must exist too. Parts whose code is absent are returned
// as pending notes.
func checkAll(files []goFile, schemaPresent bool) (vs []Violation, pending []string) {
	var st state
	for _, g := range files {
		if g.Test {
			continue
		}
		for _, d := range g.File.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok {
				continue
			}
			switch {
			case g.in(fleetsqlDir) && fd.Name.Name == "SignServerLeaf":
				st.signLeaf = true
			case g.in(fleetsqlDir) && fd.Name.Name == "serverSigner":
				st.serverSigner = true
			case g.in(dialDir) && fd.Name.Name == "PinnedRoots":
				st.pinnedRoots = true
			}
		}
	}
	if schemaPresent && !st.signLeaf {
		vs = append(vs, Violation{"FCS-1", "half-landed", fleetsqlDir, "a fleet_server_ca migration exists but fleetsql has no SignServerLeaf: the server CA must be usable only through it"})
	}
	if st.serverSigner && !st.signLeaf {
		vs = append(vs, Violation{"FCS-1", "half-landed", fleetsqlDir, "serverSigner exists without SignServerLeaf"})
	}
	if !st.signLeaf {
		pending = append(pending, "FCS-1/FCS-2 server CA signing and SignServerLeaf output (code not landed: ADR-0008 follow-on build tickets, T-0715)")
	}
	if !st.pinnedRoots {
		pending = append(pending, "FCS-4 dial roots are exactly the pinned certificates (dial.PinnedRoots not landed: dial roots-vs-client-CA split ticket)")
	}
	for _, g := range files {
		if g.Test || g.in("tools/fitness/fleetca") {
			continue
		}
		checkFCS1(g, &vs)
		if g.in(fleetsqlDir) {
			checkFCS2(g, &vs)
		}
		checkFCS3(g, &vs)
		if g.in(dialDir) && st.pinnedRoots {
			checkFCS4(g, &vs)
		}
		if g.in(composeDir) || g.in(fleetDir) {
			checkFCS6(g, &vs)
		}
	}
	return vs, pending
}

func funcs(g goFile, fn func(fd *ast.FuncDecl)) {
	for _, d := range g.File.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok && fd.Body != nil {
			fn(fd)
		}
	}
}

func isSel(n ast.Node, pkg, name string) bool {
	s, ok := n.(*ast.SelectorExpr)
	if !ok || s.Sel.Name != name {
		return false
	}
	x, ok := s.X.(*ast.Ident)
	return ok && (pkg == "" || x.Name == pkg)
}

// checkFCS1: the server CA key is used only by SignServerLeaf (and createServerCA), the table is named
// only in fleetsql, and certificate creation in fleetsql happens only in the known issuers.
func checkFCS1(g goFile, vs *[]Violation) {
	inFleetsql := g.in(fleetsqlDir)
	funcs(g, func(fd *ast.FuncDecl) {
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.CallExpr:
				name := ""
				switch f := x.Fun.(type) {
				case *ast.Ident:
					name = f.Name
				case *ast.SelectorExpr:
					name = f.Sel.Name
				}
				if name == "serverSigner" && !(inFleetsql && serverSignerCallers[fd.Name.Name]) {
					*vs = append(*vs, Violation{"FCS-1", "signer-callers", g.where(x.Pos()), "serverSigner called from " + fd.Name.Name + ": only SignServerLeaf and createServerCA may use the server CA key"})
				}
				if isSel(x.Fun, "x509", "CreateCertificate") && inFleetsql && !signAllowed[fd.Name.Name] {
					*vs = append(*vs, Violation{"FCS-1", "create-certificate", g.where(x.Pos()), "x509.CreateCertificate in " + fd.Name.Name + ": certificates are minted only by createCA, issue, createServerCA and SignServerLeaf"})
				}
			}
			return true
		})
	})
	if inFleetsql {
		return
	}
	ast.Inspect(g.File, func(n ast.Node) bool {
		if x, ok := n.(*ast.BasicLit); ok && x.Kind == token.STRING {
			if s, err := strconv.Unquote(x.Value); err == nil && strings.Contains(s, "fleet_server_ca") {
				*vs = append(*vs, Violation{"FCS-1", "table-owner", g.where(x.Pos()), "fleet_server_ca named outside fleetsql: the server CA row is read only where the signer lives"})
			}
		}
		return true
	})
}

func typeText(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.SelectorExpr:
		return typeText(t.X) + "." + t.Sel.Name
	case *ast.StarExpr:
		return "*" + typeText(t.X)
	case *ast.ArrayType:
		return "[]" + typeText(t.Elt)
	case *ast.Ellipsis:
		return "..." + typeText(t.Elt)
	}
	return "?"
}

// checkFCS2: the static half of "SignServerLeaf output is ServerAuth-only and accepts no caller key".
func checkFCS2(g goFile, vs *[]Violation) {
	funcs(g, func(fd *ast.FuncDecl) {
		if fd.Name.Name != "SignServerLeaf" {
			return
		}
		for _, f := range fd.Type.Params.List {
			t := typeText(f.Type)
			for _, bad := range forbiddenLeafParam {
				if strings.Contains(t, bad) {
					*vs = append(*vs, Violation{"FCS-2", "caller-key", g.where(f.Pos()), "SignServerLeaf takes a " + t + ": it never accepts a CSR or a key, it generates its own P-256 key"})
				}
			}
		}
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			switch {
			case isSel(n, "x509", "ExtKeyUsageClientAuth"), isSel(n, "x509", "ExtKeyUsageAny"):
				*vs = append(*vs, Violation{"FCS-2", "eku", g.where(n.Pos()), "SignServerLeaf names a ClientAuth or any EKU: a server leaf is ServerAuth only"})
			}
			if kv, ok := n.(*ast.KeyValueExpr); ok {
				if k, ok := kv.Key.(*ast.Ident); ok {
					switch k.Name {
					case "URIs":
						*vs = append(*vs, Violation{"FCS-2", "uri-san", g.where(kv.Pos()), "a server leaf carries no URI SAN (no tenant or component identity in it)"})
					case "IsCA":
						if v, ok := kv.Value.(*ast.Ident); ok && v.Name == "true" {
							*vs = append(*vs, Violation{"FCS-2", "is-ca", g.where(kv.Pos()), "a server leaf is not a CA"})
						}
					}
				}
			}
			return true
		})
	})
}

// checkFCS3: the gateway, and the fleetsql functions that feed the client pool, never touch the server CA.
func checkFCS3(g goFile, vs *[]Violation) {
	report := func(p token.Pos, what string) {
		*vs = append(*vs, Violation{"FCS-3", "client-pool", g.where(p), what + ": the server CA is never in the gateway client pool or TenantCAs"})
	}
	scan := func(root ast.Node) {
		ast.Inspect(root, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.Ident:
				if strings.Contains(strings.ToLower(x.Name), "servercert") || strings.Contains(strings.ToLower(x.Name), "serverca") {
					report(x.Pos(), "identifier "+x.Name)
				}
			case *ast.BasicLit:
				if x.Kind == token.STRING && strings.Contains(x.Value, "fleet_server_ca") {
					report(x.Pos(), "fleet_server_ca named")
				}
			}
			return true
		})
	}
	switch {
	case g.in(gatewayDir):
		// The gateway presents a server certificate it is handed (tls.Certificate), so only the CA
		// names are forbidden here, not "server certificate".
		ast.Inspect(g.File, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.Ident:
				if strings.Contains(strings.ToLower(x.Name), "serverca") {
					report(x.Pos(), "identifier "+x.Name)
				}
			case *ast.BasicLit:
				if x.Kind == token.STRING && strings.Contains(x.Value, "fleet_server_ca") {
					report(x.Pos(), "fleet_server_ca named")
				}
			}
			return true
		})
	case g.in(fleetsqlDir):
		funcs(g, func(fd *ast.FuncDecl) {
			if fd.Name.Name == "TenantCAs" || fd.Name.Name == "loadCAs" || fd.Name.Name == "bundlePEM" {
				scan(fd.Body)
			}
		})
	}
}

// checkFCS4: once PinnedRoots exists, every TLS config in dial is rooted on it (or on an empty pool for
// the handshake that only collects the chain), never on the whole bundle.
func checkFCS4(g goFile, vs *[]Violation) {
	funcs(g, func(fd *ast.FuncDecl) {
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			c, ok := n.(*ast.CallExpr)
			if !ok || len(c.Args) == 0 {
				return true
			}
			if id, ok := c.Fun.(*ast.Ident); !ok || id.Name != "clientTLS" {
				return true
			}
			if !rootOK(c.Args[0]) {
				*vs = append(*vs, Violation{"FCS-4", "dial-roots", g.where(c.Pos()), "dial roots must be Pool(PinnedRoots(...)) or an empty pool: a tenant CA from the bundle is never a TLS root for the server"})
			}
			return true
		})
	})
}

func rootOK(e ast.Expr) bool {
	c, ok := e.(*ast.CallExpr)
	if !ok {
		return false
	}
	if isSel(c.Fun, "x509", "NewCertPool") {
		return true
	}
	if id, ok := c.Fun.(*ast.Ident); ok && id.Name == "Pool" && len(c.Args) == 1 {
		if in, ok := c.Args[0].(*ast.CallExpr); ok {
			if f, ok := in.Fun.(*ast.Ident); ok && f.Name == "PinnedRoots" {
				return true
			}
		}
	}
	return false
}

// checkFCS6: no tls.Certificate literal builds its chain with a length other than 2 or by appending.
func checkFCS6(g goFile, vs *[]Violation) {
	ast.Inspect(g.File, func(n ast.Node) bool {
		cl, ok := n.(*ast.CompositeLit)
		if !ok || !strings.HasSuffix(typeText(cl.Type), "tls.Certificate") {
			return true
		}
		for _, el := range cl.Elts {
			kv, ok := el.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			if k, ok := kv.Key.(*ast.Ident); !ok || k.Name != "Certificate" {
				continue
			}
			switch v := kv.Value.(type) {
			case *ast.CompositeLit:
				if len(v.Elts) != 2 {
					*vs = append(*vs, Violation{"FCS-6", "chain-length", g.where(v.Pos()), "the presented chain has " + strconv.Itoa(len(v.Elts)) + " certificate(s): exactly [leaf, server CA]"})
				}
			case *ast.CallExpr:
				if id, ok := v.Fun.(*ast.Ident); ok && id.Name == "append" {
					*vs = append(*vs, Violation{"FCS-6", "chain-append", g.where(v.Pos()), "the chain is built by append: it must be the literal [leaf, server CA]"})
				}
			}
		}
		return true
	})
}
