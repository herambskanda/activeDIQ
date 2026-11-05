package ad

import (
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strings"

	"github.com/go-krb5/krb5/client"
	"github.com/go-krb5/krb5/config"
	krb5gssapi "github.com/go-krb5/krb5/gssapi"
	"github.com/go-krb5/krb5/iana/etypeID"
	"github.com/go-krb5/krb5/keytab"
	"github.com/go-ldap/ldap/v3"

	"github.com/skenzeriq/activediq/internal/connector/ad/gssapi"
	"github.com/skenzeriq/activediq/internal/platform/secret"
)

// Kerberos is the primary connector identity (threat-model TM-TB3-T3, feasibility §2.4): a keytab
// for a gMSA-derived or service account, used for a SASL GSSAPI bind over LDAPS. Every bind carries
// the RFC 5929 tls-server-end-point channel binding of the certificate the DC actually presented,
// and negotiates security layer "none" (AD forbids a SASL layer on top of TLS; TLS protects the
// channel). Set it instead of Credential.
type Kerberos struct {
	Principal string        // account name in the keytab, without the realm (for a gMSA: name$)
	Realm     string        // Kerberos realm, upper case DNS domain name
	Keytab    secret.Secret // keytab file contents; exposed only while the Kerberos client is built
	// KDCs are host or host:port (default 88). Empty means DNS SRV discovery for the realm.
	KDCs []string
}

func (Kerberos) String() string   { return "ad.Kerberos{redacted}" }
func (Kerberos) GoString() string { return "ad.Kerberos{redacted}" }

var (
	realmRe = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]{0,253}[A-Za-z0-9])?$`)
	// A principal name is placed in no config text, but keep it to what AD accepts in a keytab.
	principalRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._$-]{0,63}$`)
)

func (k Kerberos) validate() error {
	if !principalRe.MatchString(k.Principal) || !realmRe.MatchString(k.Realm) || k.Keytab.IsEmpty() {
		return fail(CodeInvalidArgument, "kerberos identity needs principal, realm and keytab", nil)
	}
	for _, kdc := range k.KDCs {
		h, p := splitKDC(kdc)
		if h == "" || (!realmRe.MatchString(h) && !isIP(h)) {
			return fail(CodeInvalidArgument, "kerberos KDC must be host or host:port", nil)
		}
		if p != "" && !isPort(p) {
			return fail(CodeInvalidArgument, "kerberos KDC port invalid", nil)
		}
	}
	return nil
}

func isIP(s string) bool { _, err := netip.ParseAddr(s); return err == nil }

func isPort(p string) bool {
	if p == "" || len(p) > 5 {
		return false
	}
	n := 0
	for _, c := range p {
		if c < '0' || c > '9' {
			return false
		}
		n = n*10 + int(c-'0')
	}
	return n > 0 && n < 65536
}

func splitKDC(s string) (host, port string) {
	if h, p, err := net.SplitHostPort(s); err == nil {
		return h, p
	}
	return s, ""
}

// krb5Config builds the client configuration as a typed struct: no krb5.conf text is formatted
// from realm or KDC input, so no input can add a stanza or a relation. Only AES enctypes are
// requested: RC4 is never offered.
func (k Kerberos) krb5Config() *config.Config {
	c := config.New()
	aesNames := []string{"aes256-cts-hmac-sha1-96", "aes128-cts-hmac-sha1-96"}
	aesIDs := []int32{etypeID.AES256_CTS_HMAC_SHA1_96, etypeID.AES128_CTS_HMAC_SHA1_96}
	ld := &c.LibDefaults
	ld.DefaultRealm = k.Realm
	ld.DNSLookupKDC = len(k.KDCs) == 0
	ld.DNSLookupRealm = false
	ld.UDPPreferenceLimit = 1
	ld.DefaultTktEnctypes = append([]string(nil), aesNames...)
	ld.DefaultTGSEnctypes = append([]string(nil), aesNames...)
	ld.PermittedEnctypes = append([]string(nil), aesNames...)
	ld.DefaultTktEnctypeIDs = append([]int32(nil), aesIDs...)
	ld.DefaultTGSEnctypeIDs = append([]int32(nil), aesIDs...)
	ld.PermittedEnctypeIDs = append([]int32(nil), aesIDs...)
	if len(k.KDCs) > 0 {
		r := config.Realm{Realm: k.Realm}
		for _, kdc := range k.KDCs {
			h, p := splitKDC(kdc)
			if p == "" {
				p = "88"
			}
			r.KDC = append(r.KDC, net.JoinHostPort(h, p))
		}
		c.Realms = []config.Realm{r}
	}
	return c
}

// bindGSSAPI performs the SASL GSSAPI bind on conn. spnHost is the DC's DNS name (never an IP
// literal: the SPN is ldap/<fqdn>); the channel binding comes from conn's own TLS state.
func bindGSSAPI(conn *ldap.Conn, k Kerberos, spnHost string) error {
	if isIP(spnHost) {
		return fail(CodeInvalidArgument, "GSSAPI needs the DC's DNS name (set ServerName), not an IP address", nil)
	}
	state, ok := conn.TLSConnectionState()
	cb, err := gssapi.ChannelBindingFromTLS(state, ok)
	if err != nil {
		return fail(CodeBindFailed, "no channel binding", nil)
	}
	return bindWithKeytab(conn, k, cb, spnHost)
}

// bindWithKeytab parses the keytab, runs the handshake and wipes the parsed keys on every path.
func bindWithKeytab(conn *ldap.Conn, k Kerberos, cb *krb5gssapi.ChannelBinding, spnHost string) error {
	conf := k.krb5Config()
	var kt *keytab.Keytab
	var ktErr error
	k.Keytab.Expose(func(b []byte) {
		kt = keytab.New()
		ktErr = kt.Unmarshal(b)
	})
	defer zeroKeytab(kt)
	if ktErr != nil {
		return fail(CodeInvalidArgument, "keytab unreadable", nil)
	}
	if keytabParsed != nil {
		keytabParsed(kt)
	}
	return gssapiHandshake(conn, k, kt, conf, cb, spnHost)
}

// keytabParsed is a test seam: it receives the parsed keytab so a test can inspect it after the
// bind returns. It is nil in production.
var keytabParsed func(*keytab.Keytab)

// zeroKeytab wipes every parsed key in kt. The Secret holding the keytab bytes is wiped by its
// owner; this clears the parsed copy, which the Kerberos client otherwise leaves on the heap.
func zeroKeytab(kt *keytab.Keytab) {
	if kt == nil {
		return
	}
	for i := range kt.Entries {
		clear(kt.Entries[i].Key.KeyValue)
	}
}

// newKerberosClient builds the Kerberos client with PA-REQ-ENC-PA-REP (RFC 6806 FAST negotiation) switched
// off. A Windows Server 2025 KDC answers that request by setting the EncPARep flag in the AS-REP without
// PA-FX-FAST in the encrypted pa-data, and go-krb5's AS-REP check (messages/kdc_rep.go) then fails the login
// with "KDC did not respond appropriately to FAST negotiation" (T-0846). We use no FAST armor, so nothing
// else depends on the negotiation; Samba never sets the flag, so only a Windows lab proves this path.
func newKerberosClient(k Kerberos, kt *keytab.Keytab, conf *config.Config) *client.Client {
	return client.NewWithKeytab(k.Principal, k.Realm, kt, conf, client.DisablePAFXFAST(true))
}

func gssapiHandshake(conn *ldap.Conn, k Kerberos, kt *keytab.Keytab, conf *config.Config, cb *krb5gssapi.ChannelBinding, spnHost string) error {
	krb := newKerberosClient(k, kt, conf)
	defer krb.Destroy()
	g := gssapi.New(krb, cb)
	spn := "ldap/" + strings.ToLower(strings.TrimSuffix(spnHost, "."))
	if err := conn.GSSAPIBind(g, spn, ""); err != nil {
		if le, ok := err.(*ldap.Error); ok {
			return fail(CodeBindFailed, "ldap result "+fmt.Sprint(int(le.ResultCode)), nil)
		}
		return fail(CodeBindFailed, "gssapi handshake failed", nil)
	}
	return nil
}
