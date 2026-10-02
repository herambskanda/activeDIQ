// Package krb5gssapi is the T-0023 spike: an ldap.GSSAPIClient (go-ldap v3) backed by go-krb5/krb5, with
// RFC 5929 tls-server-end-point channel binding. Spike code: it proves a bind, it is not the product adapter.
//
// What the adapter does, per RFC 4752 §3.1 and RFC 4121:
//
//  1. InitSecContext(nil): service ticket for the SPN, raw KRB5 AP-REQ (not SPNEGO) with mutual-auth, and the
//     channel-binding hash in the authenticator checksum's Bnd field (+ the MS-KILE KERB_AP_OPTIONS_CBT bit).
//  2. InitSecContext(AP-REP): decrypt the AP-REP under the ticket session key, check it echoes our ctime/cusec
//     (proof the DC holds the service key), keep the acceptor subkey.
//  3. NegotiateSaslAuth: unwrap the server's security-layer offer, answer "no security layer" — the TLS channel
//     provides integrity and confidentiality, and AD forbids negotiating a SASL layer on top of TLS.
package krb5gssapi

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/go-krb5/krb5/client"
	"github.com/go-krb5/krb5/crypto"
	"github.com/go-krb5/krb5/gssapi"
	"github.com/go-krb5/krb5/iana/keyusage"
	"github.com/go-krb5/krb5/messages"
	"github.com/go-krb5/krb5/spnego"
	"github.com/go-krb5/krb5/types"
)

// Client implements ldap.GSSAPIClient. One Client serves one bind: create it after the TLS handshake (the
// channel binding is derived from the server certificate the connection actually presented).
type Client struct {
	krb *client.Client
	cb  *gssapi.ChannelBinding // nil: send no channel binding (used only to prove the DC rejects that)

	// per-context state, zeroed by DeleteSecContext
	ekey      types.EncryptionKey // ticket session key
	subkey    types.EncryptionKey // acceptor subkey from the AP-REP (optional)
	sentCTime int64
	sentCusec int
	mutualOK  bool
	lastEType int32 // survives DeleteSecContext; not secret
}

// New returns a Client. cb may be nil to bind without channel binding.
func New(krb *client.Client, cb *gssapi.ChannelBinding) *Client {
	return &Client{krb: krb, cb: cb}
}

// ChannelBindingFromTLS derives the tls-server-end-point binding (RFC 5929 §4) from the leaf certificate the
// server presented on this connection. It refuses a non-TLS connection: a SASL bind on clear text is not allowed.
func ChannelBindingFromTLS(state tls.ConnectionState, ok bool) (*gssapi.ChannelBinding, error) {
	if !ok {
		return nil, errors.New("connection is not TLS: refusing to build a channel binding for a clear-text bind")
	}
	return gssapi.NewChannelBindingTLSServerEndPointFromState(&state)
}

// ChannelBindingFromCert is the same for a certificate in hand.
func ChannelBindingFromCert(c *x509.Certificate) (*gssapi.ChannelBinding, error) {
	return gssapi.NewChannelBindingTLSServerEndPoint(c)
}

// InitSecContext implements ldap.GSSAPIClient.
func (c *Client) InitSecContext(target string, token []byte) ([]byte, bool, error) {
	return c.InitSecContextWithOptions(target, token, nil)
}

// InitSecContextWithOptions implements ldap.GSSAPIClient.
func (c *Client) InitSecContextWithOptions(target string, in []byte, apOptions []int) ([]byte, bool, error) {
	if in == nil {
		return c.initiate(target, apOptions)
	}
	return c.finish(in)
}

func (c *Client) initiate(spn string, apOptions []int) ([]byte, bool, error) {
	tkt, ekey, err := c.krb.GetServiceTicket(spn)
	if err != nil {
		return nil, false, fmt.Errorf("service ticket for %q: %w", spn, err)
	}
	c.ekey = ekey
	c.lastEType = ekey.KeyType

	flags := []int{gssapi.ContextFlagInteg, gssapi.ContextFlagConf, gssapi.ContextFlagMutual}
	var opts []spnego.KRB5TokenOption
	if c.cb != nil {
		opts = append(opts, spnego.ChannelBinding(c.cb))
	}
	mt, err := spnego.NewKRB5TokenAPREQ(c.krb, tkt, ekey, flags, apOptions, opts...)
	if err != nil {
		return nil, false, fmt.Errorf("build AP-REQ: %w", err)
	}
	c.sentCTime = mt.APReq.Authenticator.CTime.Unix()
	c.sentCusec = mt.APReq.Authenticator.Cusec

	out, err := mt.Marshal()
	if err != nil {
		return nil, false, fmt.Errorf("marshal AP-REQ: %w", err)
	}
	return out, true, nil // an AP-REP is expected back
}

func (c *Client) finish(in []byte) ([]byte, bool, error) {
	var mt spnego.KRB5Token
	if err := mt.Unmarshal(in); err != nil {
		return nil, false, fmt.Errorf("server context token is not a KRB5 token: %w", err)
	}
	if mt.IsKRBError() {
		return nil, false, fmt.Errorf("KDC/acceptor KRB-ERROR: %w", mt.KRBError)
	}
	if !mt.IsAPRep() {
		return nil, false, errors.New("server context token is neither AP-REP nor KRB-ERROR")
	}
	plain, err := crypto.DecryptEncPart(mt.APRep.EncPart, c.ekey, keyusage.AP_REP_ENCPART)
	if err != nil {
		return nil, false, fmt.Errorf("AP-REP does not decrypt under the session key (acceptor is not the service): %w", err)
	}
	var enc messages.EncAPRepPart
	if err := enc.Unmarshal(plain); err != nil {
		return nil, false, fmt.Errorf("AP-REP enc-part: %w", err)
	}
	if enc.CTime.Unix() != c.sentCTime || enc.Cusec != c.sentCusec {
		return nil, false, errors.New("AP-REP echoes a different ctime/cusec: it answers another exchange")
	}
	c.subkey = enc.Subkey
	c.mutualOK = true
	// Context established; the empty token makes go-ldap send the empty SASL continuation that RFC 4752 §3.1
	// requires before the server's security-layer offer arrives.
	return []byte{}, false, nil
}

// NegotiateSaslAuth implements ldap.GSSAPIClient: RFC 4752 §3.1 second round. Only "no security layer" is ever
// selected; the transport is TLS.
func (c *Client) NegotiateSaslAuth(in []byte, authzid string) ([]byte, error) {
	if !c.mutualOK {
		return nil, errors.New("context not established (no verified AP-REP)")
	}
	var wt gssapi.WrapToken
	if err := wt.Unmarshal(in, true); err != nil {
		return nil, fmt.Errorf("server security-layer offer: %w", err)
	}
	// RFC 4121 §4.2.2: when the acceptor asserted a subkey in the AP-REP, tokens in both directions use it and
	// say so with the AcceptorSubkey flag; otherwise the ticket session key is used.
	key, flags := c.ekey, byte(0)
	if len(c.subkey.KeyValue) != 0 {
		key, flags = c.subkey, gssapi.FlagAcceptorSubkey
	}
	if (wt.Flags&gssapi.FlagAcceptorSubkey != 0) != (len(c.subkey.KeyValue) != 0) {
		return nil, errors.New("acceptor-subkey flag on the server's token disagrees with its AP-REP")
	}
	if wt.Flags&gssapi.FlagSealed != 0 {
		return nil, errors.New("server offer is sealed; RFC 4752 requires an integrity-only wrap token")
	}
	ok, err := wt.Verify(key, keyusage.GSSAPI_ACCEPTOR_SEAL)
	if err != nil || !ok {
		return nil, fmt.Errorf("server security-layer offer failed its checksum: %v", err)
	}
	if len(wt.Payload) != 4 {
		return nil, fmt.Errorf("server security-layer offer is %d bytes, want 4", len(wt.Payload))
	}
	if wt.Payload[0]&byte(gssapi.SecurityLayerNone) == 0 {
		return nil, fmt.Errorf("server does not offer 'no security layer' (offer=%#02x): refusing a SASL layer on top of TLS", wt.Payload[0])
	}

	resp := append([]byte{byte(gssapi.SecurityLayerNone), 0, 0, 0}, authzid...) // layer=none, maxbuf=0
	et, err := crypto.GetEType(key.KeyType)
	if err != nil {
		return nil, err
	}
	out := gssapi.WrapToken{
		Flags:     flags, // initiator, unsealed
		EC:        uint16(et.GetHMACBitLength() / 8),
		SndSeqNum: 0,
		Payload:   resp,
	}
	if err := out.SetCheckSum(key, keyusage.GSSAPI_INITIATOR_SEAL); err != nil {
		return nil, err
	}
	return out.Marshal()
}

// SessionEType reports the encryption type of the service-ticket session key (0 before a ticket is obtained). It
// is read before the bind returns, because DeleteSecContext wipes it; used by the spike to prove AES was used.
func (c *Client) SessionEType() int32 { return c.lastEType }

// DeleteSecContext implements ldap.GSSAPIClient and wipes the context keys.
func (c *Client) DeleteSecContext() error {
	for _, k := range []*types.EncryptionKey{&c.ekey, &c.subkey} {
		clear(k.KeyValue)
		*k = types.EncryptionKey{}
	}
	c.mutualOK = false
	return nil
}
