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
# The directory is writable by the service uid, which is the container user. Root must therefore never
# chown or chmod by path inside it: the container could swap a path component for a symlink between the
# check and the call and turn root into a write primitive on host files (security review of T-0104).
# So: refuse anything but flat, singly-linked regular files owned by uid:gid, and tighten modes as the
# service uid, never as root.
bad=$(find "$dir" -mindepth 1 ! -type f -print -quit)
if [ -n "$bad" ]; then echo "refusing $dir: '$bad' is not a regular file at depth 1 (subdirectory, symlink, FIFO...)" >&2; exit 2; fi
bad=$(find "$dir" -mindepth 1 -type f -links +1 -print -quit)
if [ -n "$bad" ]; then echo "refusing $dir: '$bad' has more than one hard link" >&2; exit 2; fi
bad=$(find "$dir" -mindepth 1 -type f \( ! -uid "$uid" -o ! -gid "$gid" \) -print -quit)
if [ -n "$bad" ]; then echo "refusing $dir: '$bad' is not owned by $uid:$gid; fix or remove it" >&2; exit 2; fi
if [ "$(id -u)" = 0 ]; then
  find "$dir" -mindepth 1 -type f -exec setpriv --reuid "$uid" --regid "$gid" --clear-groups chmod 0600 {} +
else
  find "$dir" -mindepth 1 -type f -exec chmod 0600 {} +
fi
echo "prepared $dir: owner $uid:$gid mode 0700"
