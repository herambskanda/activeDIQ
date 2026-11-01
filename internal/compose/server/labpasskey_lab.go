//go:build lab

package server

import (
	"context"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/skenzeriq/activediq/internal/compose/config"
	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/authn"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant/provision"
)

// Lab passkey seeding (T-0855), compiled only under the `lab` build tag. There is no registration
// ceremony yet (T-0573), so the end-to-end suite that signs in with a Chromium virtual authenticator
// needs a way to store the public half of a credential it generated itself. This is it:
//
//	activediq-server account add-passkey --account ID --credential-id B64URL --public-key B64URL --user-handle B64URL [--label TEXT]
//
// It calls WebAuthnFactor.AddCredential, the same call the ceremony will make, as an administrator action
// on the host with the server's database settings. A production build compiles neither this file nor the
// subcommand (cmd/server/account_lab.go): TestProductionBinaryHasNoPasskeySeeding builds both ways and
// fails if the command or its symbol reaches the production binary.

// LabAddPasskeyUsage is the subcommand's own usage line.
const LabAddPasskeyUsage = "usage: activediq-server account add-passkey --account ID --credential-id B64URL --public-key B64URL --user-handle B64URL [--label TEXT]   (lab builds only)"

// LabAddPasskey is `account add-passkey`. The values are base64url without padding, as the browser's
// WebAuthn API and the virtual authenticator's CDP commands carry them; the public key is a COSE_Key.
func LabAddPasskey(ctx context.Context, args []string, getenv func(string) string, stdout io.Writer) error {
	fs := flag.NewFlagSet("account add-passkey", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var account, credID, pub, handle, label string
	fs.StringVar(&account, "account", "", "")
	fs.StringVar(&credID, "credential-id", "", "")
	fs.StringVar(&pub, "public-key", "", "")
	fs.StringVar(&handle, "user-handle", "", "")
	fs.StringVar(&label, "label", "lab key", "")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || account == "" || credID == "" || pub == "" || handle == "" {
		return errors.New(LabAddPasskeyUsage)
	}
	dec := base64.RawURLEncoding.DecodeString
	var c authn.WebAuthnCredential
	var err error
	if c.CredentialID, err = dec(credID); err != nil {
		return errors.New("server: --credential-id is not base64url")
	}
	if c.PublicKey, err = dec(pub); err != nil {
		return errors.New("server: --public-key is not base64url")
	}
	if c.UserHandle, err = dec(handle); err != nil {
		return errors.New("server: --user-handle is not base64url")
	}
	c.Label = label
	cfg, err := config.Load(getenv)
	if err != nil {
		return err
	}
	if cfg.DatabaseDSN == "" {
		return ErrNoDatabase
	}
	rp, err := webAuthnRelyingParty(cfg.PublicURL)
	if err != nil {
		return err
	}
	db, err := store.Open(ctx, store.Config{DSN: cfg.DatabaseDSN})
	if err != nil {
		return fmt.Errorf("server: open store: %w", err)
	}
	defer db.Close()
	res, err := provision.FirstRun(ctx, db, firstRunTenantName) // no initialisers: finds the tenant the server created
	if err != nil {
		return fmt.Errorf("server: find the install's tenant: %w", err)
	}
	sink := audit.NewChainer(db)
	sessions, err := authn.New(authn.Config{DB: db, Audit: sink})
	if err != nil {
		return err
	}
	pending, err := authn.NewPendingStore(db, sink, nil)
	if err != nil {
		return err
	}
	wf, err := authn.NewWebAuthnFactor(rp, db, pending, sessions, sink)
	if err != nil {
		return err
	}
	id, err := wf.AddCredential(ctx, res.Tenant, account, c)
	if err != nil {
		return fmt.Errorf("server: add passkey: %w", err)
	}
	_, err = fmt.Fprintf(stdout, "Passkey %s added to account %s.\n", id, account)
	return err
}
