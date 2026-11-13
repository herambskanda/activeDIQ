package connector

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/skenzeriq/activediq/internal/connector/ad"
	"github.com/skenzeriq/activediq/internal/connector/read"
	"github.com/skenzeriq/activediq/internal/connector/rights"
	"github.com/skenzeriq/activediq/internal/connector/write"
	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/dn"
	"github.com/skenzeriq/activediq/internal/directory/ldapfilter"
	"github.com/skenzeriq/activediq/internal/platform/secret"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// backend is the connector's three handlers over one AD session, and what releases it.
type backend struct {
	verify *rights.VerifyHandler
	read   *read.Handler
	write  *write.Handler
	close  func()
}

const maxKeytabBytes = 64 << 10

// Files of the data directory. All of them survive a restart and are reloaded, never rebuilt.
const (
	baselineFile = "baseline.json"    // rights.EpochState: the reported tier0 set of the current epoch
	recordsFile  = "records.log"      // tier0 shrink / baseline-missing records
	ratchetFile  = "gate-ratchet.log" // write.GateBook ratchet appends
	pinsFile     = "c13-pins.json"    // C13 group pins
)

// adConfig is the session configuration for loc: LDAPS to the configured DCs with the customer CA,
// bound by SASL GSSAPI with the keytab identity and channel binding. There is no password credential,
// no plaintext or unvalidated option, and the keytab is held only as a secret.Secret.
func adConfig(loc Local) (ad.Config, error) {
	pem, err := readLimited(loc.CAFile, 1<<20)
	if err != nil {
		return ad.Config{}, errors.New("connector: ca_file unreadable")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return ad.Config{}, errors.New("connector: ca_file is not valid PEM")
	}
	kt, err := readLimited(loc.Kerberos.KeytabFile, maxKeytabBytes)
	if err != nil || len(kt) == 0 {
		return ad.Config{}, errors.New("connector: keytab unreadable")
	}
	return ad.Config{Servers: loc.Servers, ServerName: loc.ServerName, RootCAs: pool, PageSize: ad.DefaultPageSize,
		Kerberos: &ad.Kerberos{Principal: loc.Kerberos.Principal, Realm: loc.Kerberos.Realm,
			Keytab: secret.FromBytes(kt), KDCs: loc.Kerberos.KDCs}}, nil
}

func readLimited(path string, max int64) ([]byte, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() || fi.Size() > max {
		return nil, errors.New("unusable file")
	}
	return os.ReadFile(path)
}

// openBackend binds the AD session and builds the handlers over it. Every handler works on the one
// session, hence one DC (the pin / precondition checks depend on it). The durable files in DataDir are
// opened as they are: an existing baseline is the epoch the connector continues.
func openBackend(ctx context.Context, loc Local, log *slog.Logger) (*backend, error) {
	cfg, err := adConfig(loc)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(loc.DataDir, 0o700); err != nil {
		return nil, errors.New("connector: data_dir unusable")
	}
	sess, err := ad.Open(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("connector: open directory session: code %s", ad.CodeOf(err))
	}
	ok := false
	defer func() {
		if !ok {
			_ = sess.Close()
		}
	}()
	rd, err := sess.RootDSE(ctx)
	if err != nil {
		return nil, fmt.Errorf("connector: rootDSE: code %s", ad.CodeOf(err))
	}
	// The directory identity is the forest root NC head's objectGUID, read from the DC.
	rootRef, err := dn.ParseObjectRef(rd.RootDomainNamingContext)
	if err != nil {
		return nil, errors.New("connector: root naming context is not a DN")
	}
	head, err := sess.Read(ctx, rootRef, []string{"objectGUID"}, ad.ReadOptions{})
	if err != nil {
		return nil, fmt.Errorf("connector: read forest root: code %s", ad.CodeOf(err))
	}
	g, err := head.GUID()
	if err != nil {
		return nil, errors.New("connector: forest root has no objectGUID")
	}
	ident := &connectorv1.DirectoryIdentity{Identity: &connectorv1.DirectoryIdentity_AdForest{
		AdForest: &connectorv1.AdForestIdentity{ForestRootNcGuid: write.GUIDToWire(g)}}}
	domRef, err := dn.ParseObjectRef(rd.DefaultNamingContext)
	if err != nil {
		return nil, errors.New("connector: default naming context is not a DN")
	}
	self, err := selfRef(ctx, sess, domRef, loc.Kerberos.Principal)
	if err != nil {
		return nil, err
	}

	prov := write.NewADProvider(sess, nil, ident, &filePins{path: filepath.Join(loc.DataDir, pinsFile)})
	prov.Self = self
	src, err := read.NewADSource(sess, prov)
	if err != nil {
		return nil, errors.New("connector: read source")
	}
	rh, err := read.New(src)
	if err != nil {
		return nil, errors.New("connector: read handler")
	}
	gate, err := newGate(filepath.Join(loc.DataDir, ratchetFile), log)
	if err != nil {
		return nil, errors.New("connector: write gate")
	}
	epoch := rights.NewEpochState(rights.FileBaselineStore{Path: filepath.Join(loc.DataDir, baselineFile)},
		rights.FileRecordSink{Path: filepath.Join(loc.DataDir, recordsFile)}, nil)
	vh, err := rights.NewVerifyHandler(rights.VerifyConfig{Dir: rights.NewSessionDirectory(sess), Epoch: epoch, Identity: self,
		Directory: ident, Gate: gate, OnLocalRecordFailed: gate.CloseLocalRecordFailed, ConnectionID: loc.ConnectionID, Log: log})
	if err != nil {
		return nil, errors.New("connector: verify handler")
	}
	wh, err := write.New(prov, gate)
	if err != nil {
		return nil, errors.New("connector: write handler")
	}
	ok = true
	return &backend{verify: vh, read: rh, write: wh, close: func() { _ = sess.Close() }}, nil
}

// newGate builds the write gate over the ratchet baseline file. The baseline reports an access
// correction (contract §8.3a "baseline_acl_corrected") to the connector's local log, so a widened
// file is never narrowed silently.
func newGate(path string, log *slog.Logger) (*write.GateBook, error) {
	fb, err := write.NewFileBaseline(path, write.SlogRecorder{L: log})
	if err != nil {
		return nil, err
	}
	return write.NewGateBook(fb, nil)
}

// selfRef resolves the service account the session is bound as (its objectGUID) by sAMAccountName,
// which for a gMSA is the keytab principal with its trailing $.
func selfRef(ctx context.Context, sess *ad.Session, domain dn.ObjectRef, account string) (dn.ObjectRef, error) {
	an, err := ldapfilter.ParseAttrName("sAMAccountName", ad.DefaultSchema())
	if err != nil {
		return dn.ObjectRef{}, errors.New("connector: identity filter")
	}
	var found *guid.GUID
	err = sess.Search(ctx, ad.SearchRequest{Base: domain, Scope: ad.ScopeSubtree,
		Filter: ldapfilter.Eq(an, ldapfilter.String(account)), Attributes: []string{"objectGUID"}}, func(e *ad.Entry) error {
		eg, gerr := e.GUID()
		if gerr != nil {
			return gerr
		}
		if found != nil {
			return errors.New("ambiguous")
		}
		found = &eg
		return nil
	})
	if err != nil {
		return dn.ObjectRef{}, fmt.Errorf("connector: resolve service account: code %s", ad.CodeOf(err))
	}
	if found == nil {
		return dn.ObjectRef{}, errors.New("connector: service account not found by its account name")
	}
	return dn.GUIDRef(*found), nil
}
