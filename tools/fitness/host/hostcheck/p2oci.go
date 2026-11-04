package hostcheck

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/skenzeriq/activediq/internal/compose/profile"
	"github.com/skenzeriq/activediq/internal/platform/capability"
	"github.com/skenzeriq/activediq/tools/fitness/pgharness"
)

// P2-oci (ADR-0002 P2, OCI half; erratum E-3): the server image of every OCI manifest builds for
// linux/amd64 and linux/arm64 and boots against PostgreSQL 16 and 18, with migrations applied, health
// ready and the right tenant count. It reuses this package's build, KEK, boot and TLS helpers: one
// harness serves TM-F-HOST and P2-oci.

// Step names, in the order a case runs them. A failure names one of them.
const (
	StepManifest   = "manifest"
	StepBuild      = "build"
	StepEmulation  = "emulation"
	StepPostgres   = "postgres"
	StepMigrations = "migrations"
	StepKEK        = "kek"
	StepBoot       = "boot"
	StepHealth     = "health"
	StepTenants    = "tenants"
)

// StepError is a P2-oci failure. Its text names the profile and the step first, so a log line is enough
// to know which leg broke.
type StepError struct {
	Profile, Arch, PG, Step string
	Err                     error
}

func (e *StepError) Error() string {
	where := []string{"profile=" + e.Profile}
	if e.Arch != "" {
		where = append(where, "arch="+e.Arch)
	}
	if e.PG != "" {
		where = append(where, "postgres="+e.PG)
	}
	return fmt.Sprintf("P2-oci FAIL %s step=%s: %v", strings.Join(where, " "), e.Step, e.Err)
}

func (e *StepError) Unwrap() error { return e.Err }

// P2OCIOptions selects the matrix. The zero values of Profiles, Arches and PGVersions mean the full one.
type P2OCIOptions struct {
	Repo          string
	MigrationsDir string   // default <repo>/migrations
	Profiles      []string // default: every OCI manifest
	Arches        []string // default: amd64, arm64
	PGVersions    []string // default: 16, 18
	// RequireBoot makes an architecture that cannot run on this host a failure instead of a printed skip.
	RequireBoot bool
	Log         func(string, ...any)
}

type ociProfile struct {
	Name     string
	Manifest profile.Manifest
	// Tenants is the tenant count the booted install must hold.
	Tenants int
	// Provisioning says whether the manifest must enable the tenant-provisioning capability.
	Provisioning bool
}

// ociProfiles are the manifests that ship as an OCI image. saas is composed by internal/compose/profile,
// never named by a flag in the server: the check reads its capabilities from the manifest.
func ociProfiles() []ociProfile {
	return []ociProfile{
		{Name: "linux-oci", Manifest: profile.LinuxOCI(), Tenants: 1},
		{Name: "saas", Manifest: profile.SaaS(), Tenants: 1, Provisioning: true},
	}
}

// checkManifest is the static half: the manifest is an OCI profile, and only the hosted cell may
// provision tenants.
func (p ociProfile) checkManifest() error {
	m := p.Manifest
	if m.Name != p.Name {
		return fmt.Errorf("the composed manifest is %q", m.Name)
	}
	if m.Adapters.ServiceHost != profile.HostOCI {
		return fmt.Errorf("the manifest's service host is %q, want %q", m.Adapters.ServiceHost, profile.HostOCI)
	}
	has := capability.NewSet(m.Capabilities...).Enabled(capability.TenantProvisioning)
	if has != p.Provisioning {
		return fmt.Errorf("capability %q enabled=%v, want %v", capability.TenantProvisioning, has, p.Provisioning)
	}
	return nil
}

// P2OCI runs the matrix and returns one error per failed leg (nil when every leg passed). A leg that
// failed does not stop the others: one run shows every broken profile.
func P2OCI(ctx context.Context, o P2OCIOptions) []error {
	log := o.Log
	if log == nil {
		log = func(string, ...any) {}
	}
	if o.MigrationsDir == "" {
		o.MigrationsDir = filepath.Join(o.Repo, "migrations")
	}
	if len(o.Arches) == 0 {
		o.Arches = []string{"amd64", "arm64"}
	}
	if len(o.PGVersions) == 0 {
		o.PGVersions = []string{"16", "18"}
	}
	var profiles []ociProfile
	for _, p := range ociProfiles() {
		if len(o.Profiles) == 0 || contains(o.Profiles, p.Name) {
			profiles = append(profiles, p)
		}
	}
	var fails []error
	fail := func(p ociProfile, arch, pgv, step string, err error) {
		e := &StepError{Profile: p.Name, Arch: arch, PG: pgv, Step: step, Err: err}
		log("%s", e.Error())
		fails = append(fails, e)
	}

	ms, ps, err := pgharness.ListMigrations(o.MigrationsDir)
	if err != nil || len(ps) > 0 || len(ms) == 0 {
		for _, p := range profiles {
			fail(p, "", "", StepMigrations, fmt.Errorf("cannot list the migrations in %s: %v %v (found %d)", o.MigrationsDir, err, ps, len(ms)))
		}
		return fails
	}

	// Build every image first (the build may never be skipped), then boot those the host can run.
	type image struct {
		p        ociProfile
		arch, tg string
		bootable bool
	}
	var images []image
	nonce := strconv.FormatInt(time.Now().UnixNano(), 36)
	for _, p := range profiles {
		if err := p.checkManifest(); err != nil {
			fail(p, "", "", StepManifest, err)
			continue
		}
		log("P2-oci ok   profile=%s step=%s (service host %s, tenant-provisioning=%v)", p.Name, StepManifest, p.Manifest.Adapters.ServiceHost, p.Provisioning)
		for _, arch := range o.Arches {
			tag := "activediq-p2oci-" + p.Name + "-" + arch + ":" + nonce
			start := time.Now()
			if err := BuildImageFor(ctx, o.Repo, tag, arch, map[string]string{"io.skenzeriq.activediq.profile": p.Name}); err != nil {
				fail(p, arch, "", StepBuild, err)
				continue
			}
			log("P2-oci ok   profile=%s arch=%s step=%s linux/%s image built in %s", p.Name, arch, StepBuild, arch, time.Since(start).Round(time.Millisecond))
			images = append(images, image{p: p, arch: arch, tg: tag})
		}
	}
	defer func() {
		for _, im := range images {
			_, _ = docker(context.Background(), nil, "rmi", "-f", im.tg)
		}
	}()
	anyBootable := false
	for i := range images {
		im := &images[i]
		ok, why := canRun(ctx, im.tg, im.arch)
		im.bootable = ok
		switch {
		case ok:
			anyBootable = true
			log("P2-oci ok   profile=%s arch=%s step=%s the Docker host runs linux/%s", im.p.Name, im.arch, StepEmulation, im.arch)
		case o.RequireBoot:
			fail(im.p, im.arch, "", StepEmulation, fmt.Errorf("cannot boot linux/%s here and boot is required: %s", im.arch, why))
		default:
			log("P2-oci SKIP profile=%s arch=%s step=boot: %s (the build ran; P2_OCI_REQUIRE_BOOT=1 turns this skip into a failure)", im.p.Name, im.arch, why)
		}
	}
	if !anyBootable {
		return fails
	}

	for _, pgv := range o.PGVersions {
		pg, err := pgharness.StartServer(ctx, pgv, nil)
		if err != nil {
			for _, im := range images {
				if im.bootable {
					fail(im.p, im.arch, pgv, StepPostgres, err)
				}
			}
			continue
		}
		for _, im := range images {
			if !im.bootable {
				continue
			}
			if err := bootCase(ctx, im.p, im.arch, pgv, im.tg, pg, ms, log); err != nil {
				var se *StepError
				if !errors.As(err, &se) {
					se = &StepError{Profile: im.p.Name, Arch: im.arch, PG: pgv, Step: StepBoot, Err: err}
				}
				log("%s", se.Error())
				fails = append(fails, se)
			}
		}
		pg.Stop()
	}
	return fails
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// canRun reports whether the Docker host can execute the image's architecture. A native architecture
// passes at once. Otherwise the real image is run with an argument that makes it print its usage and exit:
// an architecture without emulation answers "exec format error" instead.
func canRun(ctx context.Context, tag, arch string) (bool, string) {
	out, err := docker(ctx, nil, "info", "--format", "{{.Architecture}}")
	if err == nil && dockerArch(strings.TrimSpace(out)) == arch {
		return true, ""
	}
	_, err = docker(ctx, nil, "run", "--rm", "--network", "none", "--platform", "linux/"+arch, tag, "kek")
	if err == nil || !strings.Contains(err.Error(), "exec format error") {
		return true, "" // the usage exit (status 2) is the expected answer; only a format error means no emulation
	}
	return false, "no emulation for linux/" + arch + " on this Docker host (exec format error; register qemu-user binfmt handlers, for example `docker run --privileged --rm tonistiigi/binfmt --install " + arch + "`)"
}

func dockerArch(s string) string {
	switch s {
	case "x86_64", "amd64":
		return "amd64"
	case "aarch64", "arm64":
		return "arm64"
	}
	return s
}

// bootCase runs migrations, boot, health and tenants for one (profile, arch, PostgreSQL) leg and returns a
// *StepError for the first step that fails.
func bootCase(ctx context.Context, p ociProfile, arch, pgv, tag string, pg *pgharness.Server, ms []pgharness.Migration, log func(string, ...any)) error {
	step := func(name string, err error) error {
		return &StepError{Profile: p.Name, Arch: arch, PG: pgv, Step: name, Err: err}
	}
	okf := func(name, f string, a ...any) {
		log("P2-oci ok   profile=%s arch=%s postgres=%s step=%s %s", p.Name, arch, pgv, name, fmt.Sprintf(f, a...))
	}
	db, err := pg.NewDatabase(ctx)
	if err != nil {
		return step(StepPostgres, err)
	}
	defer db.Drop(context.Background())
	if err := ApplyMigrations(ctx, db, ms); err != nil {
		return step(StepMigrations, err)
	}
	if n, err := TenantCount(ctx, db); err != nil || n != 0 {
		return step(StepMigrations, fmt.Errorf("after %d migrations the tenants table is not there and empty (rows %d): %v", len(ms), n, err))
	}
	okf(StepMigrations, "%d migrations applied under the owner role; tenants table present and empty", len(ms))

	kek, kekDone, err := provisionKEK(ctx, tag)
	defer kekDone()
	if err != nil {
		return step(StepKEK, err)
	}
	port, err := freePort()
	if err != nil {
		return step(StepBoot, err)
	}
	vol := "p2oci-tls-" + strconv.Itoa(port)
	defer func() { _, _ = docker(context.Background(), nil, "volume", "rm", "-f", vol) }()
	c, err := runServer(ctx, tag, append([]string{
		"ACTIVEDIQ_DATABASE_DSN=" + db.AppDSN(),
		fmt.Sprintf("ACTIVEDIQ_API_ADDR=127.0.0.1:%d", port),
		"ACTIVEDIQ_API_TLS_DIR=" + tlsMount,
	}, kek.env...), append([]string{"--platform", "linux/" + arch, "--user", fmt.Sprintf("%d:%d", serviceUID, serviceUID), "-v", vol + ":" + tlsMount}, kek.mounts()...)...)
	if err != nil {
		return step(StepBoot, err)
	}
	defer c.rm()
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	if err := waitListen(ctx, c, addr, 2*time.Minute); err != nil {
		return step(StepBoot, fmt.Errorf("%v\n%s", err, combinedLogs(ctx, c)))
	}
	okf(StepBoot, "listening on %s", addr)

	roots, err := serverRoots(ctx, c)
	if err != nil {
		return step(StepHealth, err)
	}
	if err := waitReady(roots, addr, 30*time.Second); err != nil {
		return step(StepHealth, fmt.Errorf("%v\nserver log:\n%s", err, combinedLogs(ctx, c)))
	}
	okf(StepHealth, "/health/ready answers 200 {\"status\":\"ok\"}")

	n, err := TenantCount(ctx, db)
	if err != nil {
		return step(StepTenants, err)
	}
	if n != p.Tenants {
		return step(StepTenants, fmt.Errorf("the install holds %d tenants, want exactly %d", n, p.Tenants))
	}
	if p.Provisioning {
		okf(StepTenants, "%d tenant, created by the platform provisioning path (capability %s is enabled in the composed manifest)", n, capability.TenantProvisioning)
	} else {
		okf(StepTenants, "exactly %d tenant", n)
	}
	return nil
}

// ApplyMigrations applies ms under the owner role and names the migration that fails.
func ApplyMigrations(ctx context.Context, db *pgharness.Database, ms []pgharness.Migration) error {
	failed, msg, err := pgharness.Apply(ctx, db, ms)
	if err != nil {
		return err
	}
	if failed != "" {
		return fmt.Errorf("migration %s failed: %s", failed, msg)
	}
	return nil
}

// TenantCount counts the rows of public.tenants as the database superuser, and fails when the table is
// missing: a count of zero from a database nobody migrated would prove nothing.
func TenantCount(ctx context.Context, db *pgharness.Database) (int, error) {
	c, err := db.Admin(ctx)
	if err != nil {
		return 0, err
	}
	defer c.Close(ctx)
	var n int
	if err := c.QueryRow(ctx, `SELECT count(*) FROM public.tenants`).Scan(&n); err != nil {
		return 0, fmt.Errorf("public.tenants: %w", err)
	}
	return n, nil
}

func waitReady(roots *x509.CertPool, addr string, d time.Duration) error {
	cl := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}}
	deadline := time.Now().Add(d)
	var last error
	for time.Now().Before(deadline) {
		if last = CheckReady(cl, "https://"+addr+"/health/ready"); last == nil {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("health is not ready after %s: %v", d, last)
}

// CheckReady is one readiness probe: GET url must answer 200 with the body {"status":"ok"}.
func CheckReady(cl *http.Client, url string) error {
	r, err := cl.Get(url)
	if err != nil {
		return err
	}
	defer r.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(r.Body, 4096))
	if r.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s answered %d, want 200", url, r.StatusCode)
	}
	var v struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(b, &v); err != nil || v.Status != "ok" {
		return fmt.Errorf("GET %s answered 200 with body %q, want {\"status\":\"ok\"}", url, strings.TrimSpace(string(b)))
	}
	return nil
}
