#!/bin/bash
# php-cve-check.sh [--update] [--fix]  - CVE-2026-109618 / 109619, cPanel + CloudLinux
# Exit (bitmask): 1 exposed packages | 2 stale processes | 4 accounts on an EXPOSED version
CVES='CVE-2026-10961[89]'
IGNORE="${IGNORE:-alt-php-internal-}"   # CloudLinux tooling PHP, not customer runtime
PKGRE='^(ea-php[0-9]+-php-(cli|fpm|cgi|common|litespeed)|alt-php[0-9]+-(cli|common|php-fpm|php-cgi|lsapi)|alt-php-internal-cli) '
declare -A FIXED=( [8.2]=8.2.35 [8.3]=8.3.36 [8.4]=8.4.27 [8.5]=8.5.12 )
declare -A STATUS   # branch key -> EXPOSED | IGNORED
UPDATE=0; FIX=0
for a in "$@"; do case $a in --update) UPDATE=1;; --fix) FIX=1;; esac; done
rc=0

echo "== $(hostname) $(date -u +%FT%TZ) =="

if [ "$UPDATE" = 1 ]; then
  echo "-- Updating PHP packages"
  dnf -y update 'ea-php*' 'alt-php*' || echo "dnf update failed or partial"
  echo "-- Restarting active PHP-FPM units"
  systemctl list-units --type=service --state=active --plain --no-legend 'alt-php*-fpm.service' 'ea-php*-php-fpm.service' | awk '{print $1}' | xargs -r systemctl try-restart
  /scripts/restartsrv_apache_php_fpm 2>&1 | tail -2
fi

echo "-- Pending PHP updates"
dnf -q makecache >/dev/null 2>&1
dnf -q check-update 'ea-php*' 'alt-php*' 2>/dev/null; echo "dnf exit: $? (100 = updates available)"

echo "-- mod_php"
httpd -M 2>/dev/null | grep -i php_module && echo "WARNING: mod_php loaded (highest-risk SAPI)" || echo "none"

echo "-- Packages"
while read -r name ver; do
  if [[ $name =~ ^(alt-php[0-9]+|ea-php[0-9]+)- ]]; then key=${BASH_REMATCH[1]}; else key=internal; fi
  if [[ $name == ${IGNORE}* ]]; then
    printf '%-38s %-28s IGNORED\n' "$name" "$ver"
    [ "${STATUS[$key]}" != EXPOSED ] && STATUS[$key]=IGNORED
    continue
  fi
  v=${ver%%-*}; br=$(echo "$v" | cut -d. -f1,2)
  if rpm -q --changelog "$name" | grep -qE "$CVES"; then s=PATCHED
  elif [ -n "${FIXED[$br]}" ] && [ "$(printf '%s\n%s\n' "${FIXED[$br]}" "$v" | sort -V | head -1)" = "${FIXED[$br]}" ]; then s=PATCHED
  else s=EXPOSED; rc=$((rc | 1)); STATUS[$key]=EXPOSED; fi
  printf '%-38s %-28s %s\n' "$name" "$ver" "$s"
done < <(rpm -qa --qf '%{NAME} %{VERSION}-%{RELEASE}\n' | grep -E "$PKGRE" | sort)

echo "-- /usr/bin/php (ea-php-cli wrapper: no CVE changelog, checking build date)"
bd=$(/usr/bin/php -v 2>/dev/null | head -1 | sed -nE 's/.*built: ([A-Za-z]+ +[0-9]+ [0-9]{4}).*/\1/p')
if [ -n "$bd" ] && [ "$(date -d "$bd" +%s)" -ge "$(date -d 'Oct 21 2026' +%s)" ]; then echo "built $bd PATCHED"
else echo "built ${bd:-unknown} EXPOSED"; rc=$((rc | 1)); fi

echo "-- Stale processes (old binary still in memory)"
declare -A units; manual=""
for e in /proc/[0-9]*/exe; do
  l=$(readlink "$e" 2>/dev/null) || continue
  [[ $l == *"(deleted)" && $l =~ (php|httpd|lsphp|lshttpd|litespeed) ]] || continue
  p=${e#/proc/}; p=${p%/exe}
  u=$(grep -oE '[^/]+\.service' /proc/$p/cgroup 2>/dev/null | head -1)
  echo "pid $p unit=${u:-none} $l"; rc=$((rc | 2))
  if [[ $u == *fpm*.service && $u != cpanel_php_fpm* ]]; then units[$u]=1; else manual+=" $p(${u:-none})"; fi
done
[ -z "${!units[*]}" ] && [ -z "$manual" ] && echo "none"
if [ "$FIX" = 1 ] && [ -n "${!units[*]}" ]; then
  echo "restarting: ${!units[*]}"; systemctl restart "${!units[@]}"
fi
[ -n "$manual" ] && echo "MANUAL restart needed:$manual"

echo "-- Accounts on EXPOSED/IGNORED PHP versions"
if [ ${#STATUS[@]} -eq 0 ]; then echo "none (no exposed or ignored versions)"; fi
for k in $(printf '%s\n' "${!STATUS[@]}" | sort); do
case $k in
    alt-php[0-9]*) d=${k#alt-php}; ver="${d:0:1}.${d:1}"
      users=$(selectorctl --list-users --version "$ver" 2>/dev/null | tr ',' ' ' | xargs -r -n1) ;;
    ea-php[0-9]*)
      users=$(grep -lE "^phpversion: $k\$" /var/cpanel/userdata/*/* 2>/dev/null | awk -F/ '{print $5}' | sort -u) ;;
    *) printf '%-14s %-8s n/a (internal tooling, no customer accounts)\n' "$k" "${STATUS[$k]}"; continue ;;
  esac
  n=$(printf '%s' "$users" | grep -c .)
  printf '%-14s %-8s %s user(s)' "$k" "${STATUS[$k]}" "$n"
  [ "$n" -gt 0 ] && printf ': %s' "$(echo $users)"
  printf '\n'
  [ "$n" -gt 0 ] && [ "${STATUS[$k]}" = EXPOSED ] && rc=$((rc | 4))
done

echo "RESULT $(hostname) rc=$rc"
exit $rc
