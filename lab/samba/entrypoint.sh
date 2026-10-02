#!/bin/bash
# activeDIQ AD lab entrypoint (T-0012). TEST INFRASTRUCTURE ONLY.
#   serve        start the DC in the foreground (default)
#   init         provision, seed, snapshot (one-shot; runs when the state volume is empty/stale)
#   restore      wipe the state and restore the snapshot taken by `init`
#   version      print the seed version recorded in the state volume (empty if none)
#   healthcheck  LDAPS bind as the lab service account
set -Eeuo pipefail

STATE=/var/lib/samba                 # volume: lab-state
SNAP=/snapshots                      # volume: lab-snapshots
REALM=LAB.ACTIVEDIQ.TEST
DOMAIN=LAB
BASEDN="DC=lab,DC=activediq,DC=test"
SMBCONF=/etc/samba/smb.conf
SEEDDIR=/tmp/lab-seed
TIER="${LAB_TIER:-standard}"

log() { printf '[lab] %s\n' "$*" >&2; }
need() { [ -n "${!1:-}" ] || { log "missing environment variable $1 (run via make lab-up)"; exit 2; }; }

write_smbconf() {
  cat > "$SMBCONF" <<CONF
[global]
	netbios name = DC1
	workgroup = $DOMAIN
	realm = $REALM
	server role = active directory domain controller
	dns forwarder = 127.0.0.1
	idmap_ldb:use rfc2307 = yes
	# Strong auth stays on (default): no simple bind over plain LDAP, like a hardened customer DC.
	ldap server require strong auth = yes
	tls enabled = yes
	tls cafile = $STATE/lab-tls/ca.pem
	tls certfile = $STATE/lab-tls/dc.pem
	tls keyfile = $STATE/lab-tls/dc.key
	# Lab audit trail (JSON) — the closest Samba gets to an event log.
	log level = 1 auth_audit:3 dsdb_audit:3 dsdb_password_audit:3
[sysvol]
	path = $STATE/sysvol
	read only = No
[netlogon]
	path = $STATE/sysvol/$(echo "$REALM" | tr 'A-Z' 'a-z')/scripts
	read only = No
CONF
}

make_tls() {
  local d="$STATE/lab-tls"
  mkdir -p "$d"
  openssl req -x509 -newkey rsa:3072 -nodes -days 3650 -sha256 -keyout "$d/ca.key" -out "$d/ca.pem" \
    -subj "/O=activeDIQ lab/CN=activeDIQ lab CA (test only)" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
  openssl req -newkey rsa:3072 -nodes -keyout "$d/dc.key" -out "$d/dc.csr" -subj "/CN=dc1.lab.activediq.test" 2>/dev/null
  printf 'subjectAltName=DNS:dc1.lab.activediq.test,DNS:lab.activediq.test,DNS:localhost,IP:127.0.0.1,IP:::1\nextendedKeyUsage=serverAuth\nkeyUsage=digitalSignature,keyEncipherment\n' > "$d/ext.cnf"
  openssl x509 -req -in "$d/dc.csr" -CA "$d/ca.pem" -CAkey "$d/ca.key" -CAcreateserial -days 3650 -sha256 \
    -extfile "$d/ext.cnf" -out "$d/dc.pem" 2>/dev/null
  rm -f "$d/dc.csr" "$d/ext.cnf" "$d/ca.srl"
  chmod 0600 "$d/dc.key" "$d/ca.key"
}

wait_ldaps() {
  local i
  for i in $(seq 1 120); do
    if ldapsearch -H ldaps://127.0.0.1:636 -x -s base -b "" namingContexts >/dev/null 2>&1; then return 0; fi
    sleep 1
  done
  log "DC did not answer LDAPS within 120s"; return 1
}

cmd_init() {
  need LAB_ADMIN_PASSWORD; need LAB_USER_PASSWORD; need LAB_SVC_PASSWORD; need LAB_SEED_VERSION
  export LDAPTLS_CACERT="$STATE/lab-tls/ca.pem"
  local t0=$SECONDS
  log "init: wiping state, provisioning $REALM"
  find "$STATE" -mindepth 1 -delete
  rm -f "$SNAP"/*.tar 2>/dev/null || true
  rm -f "$SMBCONF"
  samba-tool domain provision --server-role=dc --dns-backend=SAMBA_INTERNAL --use-rfc2307 \
    --realm="$REALM" --domain="$DOMAIN" --adminpass="$LAB_ADMIN_PASSWORD" --option="dns forwarder=127.0.0.1" >/dev/null
  make_tls
  write_smbconf
  # Lab password policy: complexity on (default), max age 90 days so seeded password ages mean something.
  samba-tool domain passwordsettings set --max-pwd-age=90 --min-pwd-age=0 --history-length=0 \
    --account-lockout-threshold=5 --account-lockout-duration=0 --reset-account-lockout-after=1 >/dev/null 2>&1 \
    || samba-tool domain passwordsettings set --max-pwd-age=90 --min-pwd-age=0 --history-length=0 \
    --account-lockout-threshold=5 --account-lockout-duration=99999 --reset-account-lockout-after=99999 >/dev/null

  log "init: generating seed (tier=$TIER)"
  python3 /opt/lab/seed/generate.py --tier "$TIER" --out "$SEEDDIR"
  local sam="$STATE/private/sam.ldb"
  log "init: loading seed offline into sam.ldb"
  # Each plan line: <unix epoch the clock must read | 0 = real clock> <ldbadd|ldbmodify> <file>.
  # (Samba accepts pwdLastSet only as 0/-1, so password ages come from a set-back clock — libfaketime.)
  while read -r epoch tool file; do
    if [ "$epoch" = 0 ]; then
      "$tool" -H "$sam" --relax "$SEEDDIR/$file" >"$SEEDDIR/load.log" 2>&1 || { log "load failed: $file"; tail -20 "$SEEDDIR/load.log" >&2; exit 1; }
    else
      faketime -f "@$(date -u -d "@$epoch" '+%Y-%m-%d %H:%M:%S')" \
        "$tool" -H "$sam" --relax "$SEEDDIR/$file" >"$SEEDDIR/load.log" 2>&1 || { log "load failed: $file"; tail -20 "$SEEDDIR/load.log" >&2; exit 1; }
    fi
  done < "$SEEDDIR/loadplan.txt"
  log "init: starting samba for protocol-level seed steps"
  samba --daemon --no-process-group
  wait_ldaps
  /opt/lab/seed/post-start.sh "$SEEDDIR/manifest.json"
  log "init: stopping samba, taking snapshot"
  pkill -TERM samba || true
  for _ in $(seq 1 60); do pgrep -x samba >/dev/null || break; sleep 1; done
  cp "$SEEDDIR/manifest.json" "$STATE/lab-manifest.json"
  echo "$LAB_SEED_VERSION" > "$STATE/lab-seed-version"
  mkdir -p "$SNAP"
  tar --xattrs --acls --numeric-owner -C "$STATE" -cf "$SNAP/state.tar" .
  log "init: done in $((SECONDS - t0))s (seed version $LAB_SEED_VERSION)"
}

cmd_restore() {
  [ -f "$SNAP/state.tar" ] || { log "no snapshot — run make lab-up first"; exit 1; }
  find "$STATE" -mindepth 1 -delete
  tar --xattrs --acls --numeric-owner -C "$STATE" -xf "$SNAP/state.tar"
  log "restored snapshot (seed version $(cat "$STATE/lab-seed-version"))"
}

cmd_serve() {
  [ -f "$STATE/lab-seed-version" ] || { log "state volume is empty — run make lab-up"; exit 1; }
  write_smbconf
  # Samba's internal DNS needs a resolvable name for the DC itself.
  exec samba --foreground --no-process-group
}

cmd_healthcheck() {
  need LAB_SVC_PASSWORD
  LDAPTLS_CACERT="$STATE/lab-tls/ca.pem" ldapwhoami -H ldaps://dc1.lab.activediq.test:636 -x \
    -D "svc-activediq@lab.activediq.test" -w "$LAB_SVC_PASSWORD" >/dev/null
}

case "${1:-serve}" in
  serve) cmd_serve ;;
  init) cmd_init ;;
  restore) cmd_restore ;;
  version) cat "$STATE/lab-seed-version" 2>/dev/null || true ;;
  healthcheck) cmd_healthcheck ;;
  *) exec "$@" ;;
esac
