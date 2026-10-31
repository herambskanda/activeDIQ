// Package server is the composition-root role package of cmd/server (blueprint §1, §2 rule 7). It wires
// this role's adapters and imports only what that binary may link. It boots the (still empty)
// generated module list, opens the store and runs the job worker until the process is told to stop.
package server

import (
	"context"
	"errors"
	"fmt"
	"github.com/skenzeriq/activediq/internal/platform/notify/syslog"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/skenzeriq/activediq/internal/compose/config"
	"github.com/skenzeriq/activediq/internal/directory"
	"github.com/skenzeriq/activediq/internal/directory/client"
	"github.com/skenzeriq/activediq/internal/directory/connection"
	"github.com/skenzeriq/activediq/internal/directory/inventory"
	"github.com/skenzeriq/activediq/internal/platform"
	"github.com/skenzeriq/activediq/internal/platform/apihost"
	"github.com/skenzeriq/activediq/internal/platform/apitls"
	"github.com/skenzeriq/activediq/internal/platform/capability"
	"github.com/skenzeriq/activediq/internal/webui"

	"github.com/skenzeriq/activediq/internal/platform/fleet/gateway"
	"github.com/skenzeriq/activediq/internal/platform/jobs"
	"github.com/skenzeriq/activediq/internal/platform/keys"
	"github.com/skenzeriq/activediq/internal/platform/limiter"
	"github.com/skenzeriq/activediq/internal/platform/module"
	"github.com/skenzeriq/activediq/internal/platform/operation"
	"github.com/skenzeriq/activediq/internal/platform/report"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/owners"
)

// ErrNoDatabase is returned by Run when no database DSN is configured. The server has nothing to do
// without its database, and it must say so rather than idle.
var ErrNoDatabase = errors.New("server: no database configured (" + config.EnvDatabaseDSN + ")")

// Run runs the server role until ctx is done: it boots the modules, opens the store and runs the job
// worker. getenv (os.Getenv in the binary) reads the KEK settings, which are named and validated only
// in this package (LoadKEKConfig). When ctx ends the worker stops claiming and drains; Run returns jobs.ErrDrainTimeout (wrapped)
// if running bodies ignored the forced cancellation, which the binary turns into a non-zero exit.
func Run(ctx context.Context, cfg config.Config, getenv func(string) string) error {
	if cfg.DatabaseDSN == "" {
		return ErrNoDatabase
	}
	// The identity is settled before anything is opened too: a non-loopback bind without a TLS
	// directory, or an unwritable one, fails startup here.
	kc, err := LoadKEKConfig(getenv)
	if err != nil {
		return fmt.Errorf("server: %w", err)
	}
	id, kekp, err := apiIdentityProvider(cfg, kc, time.Now())
	if err != nil {
		return err
	}
	// The rate-limit store is settled before the database is opened too: more than one node with the
	// in-memory store fails startup here, never later (TM-TB2-T7).
	if err := cfg.ValidatePrincipalStore(); err != nil {
		return fmt.Errorf("server: %w", err)
	}
	db, err := store.Open(ctx, store.Config{DSN: cfg.DatabaseDSN})
	if err != nil {
		return fmt.Errorf("server: open store: %w", err)
	}
	defer db.Close()
	// Capabilities come from the deployment profile once config selects one; no module requires
	// one yet. The directory services are built from the store, so boot follows the open.
	if _, err := boot(ctx, capability.NewSet(), directoryServices(db)); err != nil {
		return fmt.Errorf("server: boot modules: %w", err)
	}
	// The per-principal rate store and the limiter over it, mounted as the API's Limits port. A bad
	// store/node combination, budget or contract fails startup here, before the listener opens.
	ps, err := principalStore(cfg, db)
	if err != nil {
		return err
	}
	lim, err := limiter.New(limiter.Config{Principals: ps})
	if err != nil {
		return fmt.Errorf("server: rate limiter: %w", err)
	}
	// The operation runner, its audit chainer and live facts. The registry is empty until modules
	// contribute Actions; boot still asserts the minter and the wiring.
	reg, err := operation.NewRegistry()
	if err != nil {
		return fmt.Errorf("server: operation registry: %w", err)
	}
	// The connector endpoint source: a connection resolves, under the context's tenant, to its active
	// component binding's tunnel on the fleet hub (mutual TLS, established by the component). The Tier-0
	// verdict arrives in the Read header from the connector, so no separate verdict source exists.
	conns := connection.NewRegistry(db)
	src, err := client.NewTunnelSource(conns, conns, gateway.NewHub())
	if err != nil {
		return fmt.Errorf("server: connector source: %w", err)
	}
	// Lab builds only (T-0684): an env-configured lab seeds an active connection served by an in-process
	// connector; the production build's labBootstrap returns src unchanged.
	csrc, labSeed, labClose, err := labBootstrap(ctx, getenv, src)
	if err != nil {
		return err
	}
	defer labClose()
	reads, err := directoryReads(conns, csrc)
	if err != nil {
		return err
	}
	// The Tier0Context builder every write Plan and Apply carries; a missing source fails startup.
	t0, err := buildTier0(db, reads)
	if err != nil {
		return err
	}
	vopts, err := verifyOptions(csrc)
	if err != nil {
		return err
	}
	dirClient := directoryFacts(reads, append(vopts, client.WithTier0Builder(t0))...)
	authzr, err := rbacAuthorizer(db, dirClient)
	if err != nil {
		return err
	}
	dcs, err := client.NewDCDirectory(conns, csrc)
	if err != nil {
		return fmt.Errorf("server: DC directory: %w", err)
	}
	pinner, err := newDCPinner(dcs)
	if err != nil {
		return err
	}
	ok, err := buildOperation(operation.HoldsMinter, db, dirClient, authzr, reg, pinner)
	if err != nil {
		return err
	}
	// The console authentication stack: sessions, the cookie Authenticator and the step-up check. The
	// tenant-owner writer shares its session store (it ends a changed owner's sessions).
	console, err := buildConsole(db, ok.Chainer, keys.NewStore(kekp).KeySource(), slog.Default(), withPublicURL(cfg.PublicURL))
	if err != nil {
		return err
	}
	ownerWriter, err := buildOwnerAssignments(db, ok.Chainer, console.Sessions)
	if err != nil {
		return err
	}
	firstOwner, err := newFirstOwners(db, ok.Chainer, ownerWriter)
	if err != nil {
		return err
	}
	// The TM-D17 attestation routes, when the install is configured for them. Built after the
	// authorizer, which they share with the operation runner.
	tags, err := buildAttestation(cfg, db, ok.Chainer, authzr, sessionStepUp{console.StepUp})
	if err != nil {
		return err
	}
	// The SIEM destination routes (siem.destination.manage). The audit chainer is the store's sink.
	siem, err := syslog.NewStore(db, ok.Chainer)
	if err != nil {
		return err
	}
	tags = append(tags, syslog.Handlers{Store: siem}.Bind())
	// The anonymous liveness and readiness probes (AN-1). Readiness is the store answering.
	tags = append(tags, buildHealth(db, slog.Default()))
	// First-run setup (TM-TB16-T7, AN-4): an unclaimed install holds a one-time secret the installing
	// administrator reads from the setup directory; the claim route consumes it. Needs the TLS directory.
	setupTags, err := buildSetup(cfg, time.Now, firstOwner)
	if err != nil {
		return err
	}
	tags = append(tags, setupTags...)
	// directory.users.search: the connection registry for the active connection and its service-account
	// gate, the connector source for the ScopedSearch RPC (over the tunnel the connector dialled).
	dirTag, err := buildDirectory(db, conns, csrc, reads, nil)
	if err != nil {
		return err
	}
	tags = append(tags, dirTag)
	// The report run path (T-0959): the run service, its job kinds and its API. The job registry exists
	// before the API is built so the kinds register with the handlers; the retention cadence is seeded
	// once the tenant exists.
	jreg := jobs.NewRegistry()
	reportRuns, reportTag, err := buildReports(db, jreg, ok.Chainer, inventory.NewReader(db, nil), nil, cfg.BlobDir)
	if err != nil {
		return err
	}
	tags = append(tags, reportTag)
	// The sign-in plane: AN-8 for a local account, then AN-10 (TOTP, and WebAuthn when the public URL is
	// set), which is the only way a console session is created.
	tags = append(tags, console.Tags())
	cat := permissionCatalogue()
	if err := checkCatalogue(cat); err != nil {
		return err
	}
	api, err := buildAPIPorts(cfg, cat, console.ports(lim, authzr, cat), tags...)
	if err != nil {
		return err
	}
	// Modules and platform packages contribute job kinds to this registry (created above); the worker runs it.
	connKernel, err := buildConnections(db, ok.Chainer, dirClient, jreg)
	if err != nil {
		return err
	}
	// The tenant, its data key and its audit genesis exist before anything listens or the worker claims.
	tid, err := bootstrapTenant(ctx, cfg, db, ok.Chainer, kekp, jreg)
	if err != nil {
		return err
	}
	firstOwner.SetTenant(tid) // the claim route can now create the first owner
	console.SetTenant(tid)    // and the sign-in plane knows whose accounts it checks
	// Dead AN-8 throttle rows are purged on a cadence so one-off submitted names cannot grow the table (T-0868).
	if err := startThrottlePurge(ctx, db, jreg, console.Local, tid); err != nil {
		return err
	}
	// The report retention cadence is seeded for the install tenant, like the throttle purge.
	if err := startReportRetention(ctx, db, reportRuns, tid); err != nil {
		return err
	}
	// Lab builds only (T-0684): create and activate the lab connections through the real activation path.
	if err := labSeed(ctx, conns, connKernel.Service, tid); err != nil {
		return err
	}
	ln, err := net.Listen("tcp", cfg.APIAddr)
	if err != nil {
		return fmt.Errorf("server: api listen: %w", err)
	}
	srv := newAPIServer(cfg.APIAddr, api, id.TLSConfig())
	serveErr := make(chan error, 1)
	// ServeTLS with the certificate held in srv.TLSConfig: the listener never speaks plaintext.
	go func() { serveErr <- srv.ServeTLS(ln, "", "") }()
	slog.Info("server: api listening (TLS)", "addr", ln.Addr().String(), "tls_cert_sha256", id.Fingerprint)

	ops, err := startOps(cfg, id.TLSConfig())
	if err != nil {
		_ = srv.Close()
		return err
	}

	wctx, cancel := context.WithCancel(ctx)
	defer cancel()
	workerErr := make(chan error, 1)
	go func() {
		workerErr <- runWorker(wctx, db, jreg, jobs.WorkerConfig{Holder: cfg.InstanceID, ShutdownGrace: cfg.ShutdownGrace})
	}()

	var firstErr error
	select {
	case firstErr = <-workerErr:
		workerErr = nil
	case err := <-serveErr:
		firstErr = fmt.Errorf("server: api listener: %w", err)
		serveErr = nil
	case err := <-ops.err():
		firstErr = fmt.Errorf("server: ops listener: %w", err)
	}
	cancel()
	// The listener stops accepting and in-flight requests get the shutdown grace.
	sctx, scancel := context.WithTimeout(context.WithoutCancel(ctx), cfg.ShutdownGrace)
	defer scancel()
	if err := srv.Shutdown(sctx); err != nil {
		_ = srv.Close()
		if firstErr == nil {
			firstErr = fmt.Errorf("server: api shutdown: %w", err)
		}
	}
	if serveErr != nil {
		<-serveErr
	}
	if err := ops.shutdown(sctx); err != nil && firstErr == nil {
		firstErr = err
	}
	if workerErr != nil {
		if err := <-workerErr; err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// apiIdentity validates the listen address against the TLS configuration and loads or generates the
// per-install certificate.
func apiIdentity(cfg config.Config, kc KEKConfig, now time.Time) (apitls.Identity, error) {
	id, _, err := apiIdentityProvider(cfg, kc, now)
	return id, err
}

// apiIdentityProvider is apiIdentity that also returns the unlocked KEK provider, so the keystore is opened
// (and its passphrase stretched) once per boot and the same provider serves the tenant DEK source.
func apiIdentityProvider(cfg config.Config, kc KEKConfig, now time.Time) (apitls.Identity, keys.Provider, error) {
	if err := cfg.ValidateAPIListen(); err != nil {
		return apitls.Identity{}, nil, fmt.Errorf("server: %w", err)
	}
	// The KEK provider is unlocked first and any failure (no keystore, wrong passphrase, corrupt file) stops
	// startup: there is no fallback to an unsealed key and nothing is generated here.
	if err := kc.checkPlacement(cfg.APITLSDir); err != nil {
		return apitls.Identity{}, nil, fmt.Errorf("server: %w", err)
	}
	p, err := platformKeyProvider(kc)
	if err != nil {
		return apitls.Identity{}, nil, fmt.Errorf("server: key provider: %w", err)
	}
	id, err := apitls.LoadOrGenerateSealed(cfg.APITLSDir, cfg.APIAddr, now, p)
	if err != nil {
		return apitls.Identity{}, nil, fmt.Errorf("server: api tls: %w", err)
	}
	return id, p, nil
}

// buildAPIPorts makes the API handler over the given ports: Run mounts the console stack's.
func buildAPIPorts(cfg config.Config, cat apihost.Permissions, ports apihost.Ports, tags ...apihost.TagHandlers) (http.Handler, error) {
	policy, err := apihost.LoadPolicy()
	if err != nil {
		return nil, fmt.Errorf("server: api policy: %w", err)
	}
	return buildAPIPortsWith(cfg, policy, cat, ports, tags...)
}

func buildAPIPortsWith(cfg config.Config, policy apihost.Policy, cat apihost.Permissions, ports apihost.Ports, tags ...apihost.TagHandlers) (http.Handler, error) {
	doc, err := apihost.LoadDocument()
	if err != nil {
		return nil, fmt.Errorf("server: api contract: %w", err)
	}
	s, err := apihost.Build(doc, tags, policy, cat, ports, apihost.WithBodyBudget(cfg.APIBodyBudget), apihost.WithTrustedProxies(cfg.TrustedProxies), apihost.WithConsole(webui.Console()))
	if err != nil {
		return nil, fmt.Errorf("server: build api: %w", err)
	}
	return s, nil
}

// runWorker builds the worker and runs it until ctx ends. An invalid holder or setting fails here,
// before anything is claimed.
func runWorker(ctx context.Context, db *store.DB, reg *jobs.Registry, wcfg jobs.WorkerConfig) error {
	w, err := jobs.NewWorker(db, reg, wcfg)
	if err != nil {
		return fmt.Errorf("server: job worker: %w", err)
	}
	slog.Info("server: job worker started")
	if err := w.Run(ctx); err != nil {
		slog.Error("server: job worker did not drain; unfinished claims are left for the next process to rescue", "err", err)
		return fmt.Errorf("server: job worker: %w", err)
	}
	slog.Info("server: job worker stopped")
	return nil
}

// directoryServices builds the directory services handed to every module: the connection registry,
// the only writer of connections, backed by the store.
func directoryServices(db *store.DB) directory.Services {
	return directory.Services{Connection: connection.NewRegistry(db)}
}

// boot hands the generated module list to module.Boot, the only caller of it (ADR-0003 rule 5).
func boot(ctx context.Context, enabled capability.Set, dir directory.Services) (*module.Contributions, error) {
	c, _, err := bootReport(ctx, enabled, dir, owners.Lookup)
	return c, err
}

// bootReport is boot plus the EP-8 report host. The host is created first so every module receives it
// as Deps.Report, boots the modules (which checks the tables of the datasets they register), adds
// those datasets under their module's owner key and seals the host. Datasets that directory packages
// export (inventory.Datasets(), row B3) are added to the host here too, under their package's key,
// before the modules boot, and are checked by the same function.
func bootReport(ctx context.Context, enabled capability.Set, dir directory.Services, ownerOf report.TableOwners) (*module.Contributions, *report.Host, error) {
	host := report.NewHost(ownerOf)
	c, err := module.Boot(ctx, generatedModules(platform.Deps{Report: host}, dir), enabled, module.WithTableOwners(ownerOf))
	if err != nil {
		return nil, nil, err
	}
	for _, s := range c.Datasets() {
		if err := host.Add(s.Owner, s.Datasets...); err != nil {
			return nil, nil, fmt.Errorf("server: report datasets: %w", err)
		}
	}
	host.Seal()
	return c, host, nil
}
