#!/bin/sh
# Prepares the host directory that is bind-mounted as ACTIVEDIQ_API_TLS_DIR (T-0104, TM-TB16-T3):
# owned by the container's non-root service uid:gid, mode 0700. The server itself refuses a directory
# that is not owned by its user or is group/other-writable (api-pipeline.md); this makes the mount right
# so that check passes and no other local user can read the key.
# usage: prepare-tls-dir.sh <dir> [uid] [gid]    (defaults 10001 10001; needs root unless uid/gid are yours)
set -eu
dir=${1:?usage: prepare-tls-dir.sh <dir> [uid] [gid]}
uid=${2:-10001}
gid=${3:-10001}
case $uid in 0 | '' | *[!0-9]*) echo "refusing uid '$uid': the service must be a non-root numeric uid" >&2; exit 2 ;; esac
case $gid in '' | *[!0-9]*) echo "refusing gid '$gid'" >&2; exit 2 ;; esac
if [ -L "$dir" ]; then echo "refusing $dir: it is a symlink" >&2; exit 2; fi
umask 077
mkdir -p "$dir"
chown "$uid:$gid" "$dir"
chmod 0700 "$dir"
# an upgrade may leave files from an earlier layout: keep every file private
find "$dir" -mindepth 1 -type f -exec chown "$uid:$gid" {} + -exec chmod 0600 {} +
echo "prepared $dir: owner $uid:$gid mode 0700"
