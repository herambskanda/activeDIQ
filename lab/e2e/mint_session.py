#!/usr/bin/env python3
"""Create the first local console account on a lab-built server and sign it in through the real API (T-0765).

  mint_session.py SERVER_BIN BASE_URL CA_PEM USERNAME OUT_FILE

`account init-local` takes the password on stdin and prints the TOTP setup key; the key's current code confirms enrolment. Sign-in is
then the product's own two steps (POST /api/v1/auth/break-glass/password, POST /api/v1/auth/second-factor/totp/verify with the NEXT
30 s step, since enrolment spent the current one). The session cookie value goes to OUT_FILE (mode 0600) and nowhere else; the
password and the seed are random per run, never printed or written. TLS is verified against CA_PEM.
"""
import base64, hashlib, hmac, http.client, json, os, re, secrets, ssl, struct, subprocess, sys, time, urllib.parse

COOKIE = "__Host-adiq_session"


def totp(seed_b32, step):
    key = base64.b32decode(seed_b32 + "=" * (-len(seed_b32) % 8))
    h = hmac.new(key, struct.pack(">Q", step), hashlib.sha1).digest()
    o = h[-1] & 0x0F
    return f"{(struct.unpack('>I', h[o:o + 4])[0] & 0x7FFFFFFF) % 1000000:06d}"


def init_local(server_bin, username, password):
    p = subprocess.Popen([server_bin, "account", "init-local", "--username", username], stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    p.stdin.write(password + "\n"); p.stdin.flush()
    out = ""
    while True:  # read until the setup key is printed, then confirm with its current code
        c = p.stdout.read1(256) if hasattr(p.stdout, "read1") else p.stdout.read(1)
        if not c:
            break
        out += c
        m = re.search(r"setup key: ([A-Z2-7]+)\n", out)
        if m:
            seed = m.group(1)
            p.stdin.write(totp(seed, int(time.time()) // 30) + "\n"); p.stdin.close()
            out += p.stdout.read()
            break
    err = p.stderr.read()
    if p.wait() != 0 or "Authenticator confirmed" not in out:
        sys.exit("mint_session: init-local failed: " + re.sub(r"setup key: \S+", "setup key: <redacted>", err + out)[-400:])
    return seed


def post(conn, path, body, cookie=None):
    h = {"Content-Type": "application/json"}
    if cookie:
        h["Cookie"] = cookie
    conn.request("POST", path, json.dumps(body), h)
    r = conn.getresponse(); r.read()
    return r.status, [v for k, v in r.getheaders() if k.lower() == "set-cookie"]


def main(a):
    if len(a) != 6:
        sys.exit(__doc__)
    server_bin, base, ca, username, out_file = a[1:]
    u = urllib.parse.urlparse(base)
    password = "pw-" + secrets.token_hex(12)
    seed = init_local(server_bin, username, password)
    ctx = ssl.create_default_context(cafile=ca)
    conn = http.client.HTTPSConnection(u.hostname, u.port, context=ctx, timeout=30)
    st, ck = post(conn, "/api/v1/auth/break-glass/password", {"username": username, "password": password})
    if st != 204 or not ck:
        sys.exit(f"mint_session: password step answered {st}")
    pending = ck[0].split(";", 1)[0]
    st, ck = post(conn, "/api/v1/auth/second-factor/totp/verify", {"code": totp(seed, int(time.time()) // 30 + 1)}, pending)
    sess = next((c.split(";", 1)[0] for c in ck if c.startswith(COOKIE + "=")), None)
    if st != 204 or not sess:
        sys.exit(f"mint_session: second-factor step answered {st}")
    fd = os.open(out_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(sess.split("=", 1)[1])
    print(f"mint_session: signed in as {username}; session cookie written to {out_file} (mode 0600)")


if __name__ == "__main__":
    main(sys.argv)
