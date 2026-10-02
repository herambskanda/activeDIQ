// cbtbind binds to a DC with SASL/GSSAPI (Kerberos, AES-only keytab) over LDAPS or StartTLS, with or without a
// tls-server-end-point channel binding, then runs RFC 4532 "Who am I?". It never skips certificate verification.
// Exit 0: bind succeeded and whoami printed. Exit 1: bind failed (the reason is printed). Exit 2: usage.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/go-krb5/krb5/client"
	"github.com/go-krb5/krb5/config"
	"github.com/go-krb5/krb5/gssapi"
	"github.com/go-krb5/krb5/keytab"
	"github.com/go-ldap/ldap/v3"

	"github.com/skenzeriq/activediq/garage/ldap-cbt-spike/krb5gssapi"
)

func main() {
	var (
		mode       = flag.String("mode", "ldaps", "ldaps | starttls")
		addr       = flag.String("addr", "127.0.0.1:1636", "TCP address of the DC (ldaps or ldap port)")
		serverName = flag.String("servername", "dc1.lab.activediq.test", "TLS server name (certificate SAN) and SPN host")
		caFile     = flag.String("ca", "", "PEM file with the CA that signed the DC certificate (required)")
		ktFile     = flag.String("keytab", "", "keytab (AES-only) of the bind principal (required)")
		user       = flag.String("user", "svc-cbt-spike", "principal name in the keytab")
		realm      = flag.String("realm", "LAB.ACTIVEDIQ.TEST", "Kerberos realm")
		kdc        = flag.String("kdc", "127.0.0.1:1088", "KDC host:port")
		cbt        = flag.String("cbt", "server-end-point", "channel binding to send: server-end-point (correct) | none | wrong (binding of another certificate, the CA's)")
		timeout    = flag.Duration("timeout", 20*time.Second, "dial and bind timeout")
	)
	flag.Parse()
	if *caFile == "" || *ktFile == "" || (*mode != "ldaps" && *mode != "starttls") {
		flag.Usage()
		os.Exit(2)
	}
	if *cbt != "server-end-point" && *cbt != "none" && *cbt != "wrong" {
		flag.Usage()
		os.Exit(2)
	}
	if err := run(*mode, *addr, *serverName, *caFile, *ktFile, *user, *realm, *kdc, *cbt, *timeout); err != nil {
		fmt.Printf("BIND FAILED mode=%s cbt=%s: %v\n", *mode, *cbt, err)
		os.Exit(1)
	}
}

func run(mode, addr, serverName, caFile, ktFile, user, realm, kdc, cbt string, timeout time.Duration) error {
	pemBytes, err := os.ReadFile(caFile)
	if err != nil {
		return err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return fmt.Errorf("no certificates in %s", caFile)
	}
	tlsCfg := &tls.Config{RootCAs: pool, ServerName: serverName, MinVersion: tls.VersionTLS12}

	// AES-only on the wire too: the client may not even ask for RC4.
	conf, err := config.NewFromString(fmt.Sprintf(`[libdefaults]
 default_realm = %[1]s
 dns_lookup_kdc = false
 dns_lookup_realm = false
 udp_preference_limit = 1
 default_tkt_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
 default_tgs_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
 permitted_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
[realms]
 %[1]s = {
  kdc = %[2]s
 }
`, realm, kdc))
	if err != nil {
		return err
	}
	kt, err := keytab.Load(ktFile)
	if err != nil {
		return err
	}
	krb := client.NewWithKeytab(user, realm, kt, conf)
	defer krb.Destroy()

	var conn *ldap.Conn
	switch mode {
	case "ldaps":
		conn, err = ldap.DialURL("ldaps://"+addr, ldap.DialWithTLSConfig(tlsCfg), ldap.DialWithDialer(netDialer(timeout)))
	case "starttls":
		conn, err = ldap.DialURL("ldap://"+addr, ldap.DialWithDialer(netDialer(timeout)))
		if err == nil {
			err = conn.StartTLS(tlsCfg)
		}
	}
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer conn.Close()
	conn.SetTimeout(timeout)

	state, ok := conn.TLSConnectionState()
	if !ok {
		return fmt.Errorf("connection is not TLS")
	}
	var cb *gssapi.ChannelBinding
	switch cbt {
	case "server-end-point":
		if cb, err = krb5gssapi.ChannelBindingFromTLS(state, ok); err != nil {
			return err
		}
	case "wrong":
		// A well-formed tls-server-end-point binding over a certificate the DC did not present.
		blk, _ := pem.Decode(pemBytes)
		other, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return err
		}
		if cb, err = krb5gssapi.ChannelBindingFromCert(other); err != nil {
			return err
		}
	}
	g := krb5gssapi.New(krb, cb)
	fmt.Printf("TLS %s cipher=%s peer-cert-sig=%s cbt=%s\n", tlsVersion(state.Version), tls.CipherSuiteName(state.CipherSuite),
		state.PeerCertificates[0].SignatureAlgorithm, cbt)

	spn := "ldap/" + strings.ToLower(serverName)
	if err := conn.GSSAPIBind(g, spn, ""); err != nil {
		return err
	}
	who, err := conn.WhoAmI(nil)
	if err != nil {
		return fmt.Errorf("bound, but whoami failed: %w", err)
	}
	fmt.Printf("BIND OK mode=%s cbt=%s spn=%s ticket-session-etype=%d whoami=%q\n", mode, cbt, spn, g.SessionEType(), who.AuthzID)
	return nil
}

func tlsVersion(v uint16) string {
	switch v {
	case tls.VersionTLS12:
		return "1.2"
	case tls.VersionTLS13:
		return "1.3"
	}
	return fmt.Sprintf("%#x", v)
}
