#!/bin/bash
# php-find.sh - list every PHP on this host and say whether it has the
# CVE-2026-109618 / CVE-2026-109619 fix. Self-contained, read-only, run as root.
#
# One tab-separated line per finding:   host  source  name  version  status
#   source: package | binary | docker
#   status: PATCHED | EXPOSED | CHECK   (CHECK = PHP found but version not determined, look manually)
# Last line:                            host  summary  -  -  NO_PHP | ALL_PATCHED | ATTENTION
# The exit code is always 0; read the summary line.
#
# Not listed: cPanel's own PHP (/usr/local/cpanel) and CloudLinux internal PHP (/opt/alt/php-internal),
# PHP under /home or other paths outside /usr /opt /srv, and stopped containers.

main() {
  local host n=0 bad=0 CVE='CVE-2026-10961[89]'
  host=$(hostname)

  emit() {  # source name version status
    printf '%s\t%s\t%s\t%s\t%s\n' "$host" "$1" "$2" "$3" "$4"
    n=$((n+1)); [ "$4" = PATCHED ] || bad=$((bad+1))
  }
  fixed() { case $1 in 8.2) echo 8.2.35;; 8.3) echo 8.3.36;; 8.4) echo 8.4.27;; 8.5) echo 8.5.12;; esac; }
  ver_ok() {  # is this version at or above the upstream fix? (8.2 - 8.5 only)
    local v f
    v=$(echo "$1" | grep -oE '^[0-9]+\.[0-9]+\.[0-9]+') || return 1
    f=$(fixed "${v%.*}"); [ -n "$f" ] || return 1
    [ "$(printf '%s\n%s\n' "$f" "$v" | sort -V | head -1)" = "$f" ]
  }
  pkg_status() {  # package name, version: the vendor changelog naming the CVE counts as patched
    local name=$1 ver=$2 f
    if command -v dpkg-query >/dev/null 2>&1; then
      for f in /usr/share/doc/$name/changelog.Debian.gz /usr/share/doc/$name/changelog.gz; do
        [ -r "$f" ] && zcat "$f" 2>/dev/null | grep -qE "$CVE" && { echo PATCHED; return; }
      done
      ver=$(echo "$ver" | sed -E 's/^[0-9]+://')
    else
      rpm -q --changelog "$name" 2>/dev/null | grep -qE "$CVE" && { echo PATCHED; return; }
    fi
    ver_ok "$ver" && echo PATCHED || echo EXPOSED
  }

  # 1. distro, cPanel (ea-php) and CloudLinux (alt-php) packages
  local name ver
  if command -v dpkg-query >/dev/null 2>&1; then
    while read -r name ver; do
      emit package "$name" "$ver" "$(pkg_status "$name" "$ver")"
    done < <(dpkg-query -W -f='${db:Status-Abbrev} ${Package} ${Version}\n' 2>/dev/null |
      awk '$1=="ii" && $2 ~ /^(php[0-9]+[.][0-9]+-(cli|fpm|cgi|embed)|libapache2-mod-php[0-9]+[.][0-9]+)$/ {print $2, $3}')
  fi
  if command -v rpm >/dev/null 2>&1; then
    while read -r name ver; do
      emit package "$name" "$ver" "$(pkg_status "$name" "${ver%%-*}")"
    done < <(rpm -qa --qf '%{NAME} %{VERSION}-%{RELEASE}\n' 2>/dev/null |
      awk '$1 ~ /^(php|php-(cli|fpm|cgi)|mod_php|ea-php[0-9]+-php-(cli|fpm|cgi|litespeed)|alt-php[0-9]+-(cli|php-fpm|php-cgi|lsapi)|php[0-9]+u?-(php-)?(cli|fpm|cgi))$/' | sort)
  fi

  # 2. PHP binaries no package owns (hand builds, Plesk, DirectAdmin, LiteSpeed...). Never executed.
  local f
  while IFS= read -r f; do
    command -v dpkg >/dev/null 2>&1 && dpkg -S "$f" >/dev/null 2>&1 && continue
    command -v rpm >/dev/null 2>&1 && rpm -qf "$f" >/dev/null 2>&1 && continue
    emit binary "$f" not-run CHECK
  done < <(find /usr /opt /srv -maxdepth 7 -type f -perm -100 \
    \( -name php -o -name 'php[0-9]*' -o -name php-fpm -o -name 'php-fpm[0-9]*' -o -name php-cgi -o -name 'lsphp*' -o -name frankenphp \) \
    -not -path '/opt/cpanel/*' -not -path '/opt/alt/*' -not -path '/usr/local/cpanel/*' \
    -not -path '/usr/share/*' -not -path '/usr/lib/php/*' 2>/dev/null)

  # 3. running Docker containers
  local ENVFMT='{{range .Config.Env}}{{println .}}{{end}}'
  local PROBE='for b in php php-fpm /usr/local/bin/php /usr/local/sbin/php-fpm /usr/bin/php[0-9]* /usr/sbin/php-fpm[0-9]*; do command -v "$b" >/dev/null 2>&1 || [ -x "$b" ] || continue; v=$("$b" -n -v 2>/dev/null | head -1); echo "$v" | grep -qE "^PHP [0-9]" && { echo "$v"; break; }; done'
  local PROBE_CL='zcat /usr/share/doc/php*/changelog*.gz 2>/dev/null | grep -qE "CVE-2026-10961[89]" && echo Y'
  if command -v docker >/dev/null 2>&1; then
    if docker info >/dev/null 2>&1; then
      local c envs pv cname cimg st cl
      for c in $(docker ps -q); do
        envs=$(docker inspect -f "$ENVFMT" "$c" 2>/dev/null)
        pv=$(echo "$envs" | sed -n 's/^PHP_VERSION=//p' | head -1)
        if [ -z "$pv" ]; then
          pv=$(timeout 15 docker exec "$c" sh -c "$PROBE" </dev/null 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
        fi
        [ -n "$pv" ] || continue
        cname=$(docker inspect -f '{{.Name}}' "$c"); cname=${cname#/}
        cimg=$(docker inspect -f '{{.Config.Image}}' "$c")
        st=EXPOSED; ver_ok "$pv" && st=PATCHED
        if [ "$st" = EXPOSED ]; then
          cl=$(timeout 15 docker exec "$c" sh -c "$PROBE_CL" </dev/null 2>/dev/null)
          case $cl in *Y*) st=PATCHED ;; esac
        fi
        emit docker "$cname ($cimg)" "$pv" "$st"
      done
    else
      emit docker docker-daemon unreachable CHECK
    fi
  fi

  local s=ALL_PATCHED
  [ $n -eq 0 ] && s=NO_PHP
  [ $bad -gt 0 ] && s=ATTENTION
  printf '%s\tsummary\t-\t-\t%s\n' "$host" "$s"
}

main "$@"
exit 0
