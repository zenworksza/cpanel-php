#!/bin/bash
# php-cve-check-generic.sh [--update] [--fix] [--no-docker]
# CVE-2026-109618 / 109619 on non-cPanel hosts: Debian/Ubuntu, RHEL-family, Docker.
# Exit (bitmask): 1 exposed host packages/binaries | 2 stale host processes | 4 exposed containers | 8 docker present but not scanned
CVES='CVE-2026-10961[89]'
declare -A FIXED=( [8.2]=8.2.35 [8.3]=8.3.36 [8.4]=8.4.27 [8.5]=8.5.12 )
UPDATE=0; FIX=0; DOCKER=1
for a in "$@"; do case $a in --update) UPDATE=1;; --fix) FIX=1;; --no-docker) DOCKER=0;; esac; done
rc=0; remi=0; cexp=0

if command -v dpkg-query >/dev/null 2>&1; then PM=deb
  PKGRE='^(php[0-9]+[.][0-9]+-(cli|fpm|cgi|common|embed)|libapache2-mod-php[0-9]+[.][0-9]+)$'
elif command -v rpm >/dev/null 2>&1; then PM=rpm
  PKGRE='^(php|php-(cli|fpm|cgi|common)|mod_php|php[0-9]+u?-(php-)?(cli|fpm|cgi|common))$'
else PM=none; fi

list_pkgs() {
  case $PM in
    deb) dpkg-query -W -f='${db:Status-Abbrev} ${Package} ${Version}\n' 2>/dev/null | awk -v re="$PKGRE" '$1=="ii" && $2 ~ re {print $2, $3}' ;;
    rpm) rpm -qa --qf '%{NAME} %{VERSION}-%{RELEASE}\n' | awk -v re="$PKGRE" '$1 ~ re' ;;
  esac | sort
}

ver_ok() {  # 0 if version is at/above the upstream fix (8.2-8.5 only)
  local v br
  v=$(echo "$1" | grep -oE '^[0-9]+\.[0-9]+\.[0-9]+') || return 1
  br=${v%.*}; [ -n "${FIXED[$br]}" ] || return 1
  [ "$(printf '%s\n%s\n' "${FIXED[$br]}" "$v" | sort -V | head -1)" = "${FIXED[$br]}" ]
}

pkg_status() {  # name fullversion -> PATCHED|EXPOSED
  local name=$1 ver=$2 v f
  if [ "$PM" = deb ]; then
    v=$(echo "$ver" | sed -E 's/^[0-9]+://; s/[-+~].*//')
    for f in /usr/share/doc/$name/changelog.Debian.gz /usr/share/doc/$name/changelog.gz; do
      [ -r "$f" ] && zcat "$f" 2>/dev/null | grep -qE "$CVES" && { echo PATCHED; return; }
    done
  else
    v=${ver%%-*}
    rpm -q --changelog "$name" 2>/dev/null | grep -qE "$CVES" && { echo PATCHED; return; }
  fi
  ver_ok "$v" && echo PATCHED || echo EXPOSED
}

echo "== $(hostname) $(date -u +%FT%TZ) pkgmgr=$PM =="

if [ "$UPDATE" = 1 ] && [ "$PM" != none ]; then
  echo "-- Updating host PHP packages"
  pkgs=$(list_pkgs | awk '{print $1}' | tr '\n' ' ')
  if [ -n "$pkgs" ]; then
    if [ "$PM" = deb ]; then apt-get update -qq; apt-get install -y --only-upgrade $pkgs
    else $(command -v dnf || command -v yum) -y upgrade $pkgs; fi
  fi
  echo "-- Restarting active PHP-FPM units"
  systemctl list-units --type=service --state=active --plain --no-legend | awk '{print $1}' \
    | grep -E '^(php[0-9.]*-fpm|php-fpm|php[0-9]+-php-fpm)[.]service$' | xargs -r systemctl try-restart
fi

echo "-- Pending host updates (apt uses cached lists; --update refreshes them)"
case $PM in
  deb) apt list --upgradable 2>/dev/null | grep -E '^(php[0-9.]+-|libapache2-mod-php)' || echo none ;;
  rpm) $(command -v dnf || command -v yum) -q check-update $(list_pkgs | awk '{print $1}') 2>/dev/null || true ;;
esac

echo "-- mod_php (host Apache)"
mp=0
for c in apache2ctl apachectl httpd; do
  command -v $c >/dev/null 2>&1 && { $c -M 2>/dev/null | grep -qiE 'php[0-9]*_module' && mp=1; break; }
done
[ $mp = 1 ] && echo "WARNING: mod_php loaded (highest-risk SAPI)" || echo none

echo "-- Host packages"
n=0
while read -r name ver; do
  n=$((n+1)); s=$(pkg_status "$name" "$ver")
  if [ "$s" = EXPOSED ]; then
    rc=$((rc|1))
    [ "$PM" = rpm ] && rpm -q --qf '%{PACKAGER}%{VENDOR}' "$name" 2>/dev/null | grep -qi remi && remi=1
  fi
  printf '%-34s %-30s %s\n' "$name" "$ver" "$s"
done < <(list_pkgs)
[ $n -eq 0 ] && echo "no distro PHP packages installed"

echo "-- Binaries not owned by a package (version check only, cannot see backports)"
declare -A seen; um=0
for b in $(command -v php php-fpm php-cgi 2>/dev/null) /usr/bin/php* /usr/sbin/php-fpm* /usr/local/bin/php* /usr/local/sbin/php-fpm* /opt/remi/php*/root/usr/bin/php /opt/remi/php*/root/usr/sbin/php-fpm; do
  [ -f "$b" ] && [ -x "$b" ] || continue
  r=$(readlink -f "$b"); [ -n "${seen[$r]}" ] && continue; seen[$r]=1
  [[ $(basename "$r") =~ ^php(-fpm|-cgi)?[0-9.]*$ ]] || continue
  if [ "$PM" = deb ]; then dpkg -S "$r" >/dev/null 2>&1 && continue
  elif [ "$PM" = rpm ]; then rpm -qf "$r" >/dev/null 2>&1 && continue; fi
  um=1; v=$(timeout 5 "$r" -n -v 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
  if ver_ok "$v"; then s=PATCHED; else s=EXPOSED; rc=$((rc|1)); fi
  printf '%-48s %-10s %s\n' "$r" "${v:-unknown}" "$s"
done
[ $um = 0 ] && echo none

echo "-- Stale host processes (old binary or libphp.so still in memory)"
declare -A units; manual=""; sn=0
for d in /proc/[0-9]*; do
  p=${d#/proc/}; l=$(readlink "$d/exe" 2>/dev/null) || continue
  st=""
  [[ $l == *"(deleted)" && $l =~ (php|httpd|apache2|lsphp|litespeed) ]] && st=$l
  [ -z "$st" ] && [[ $l =~ (httpd|apache2) ]] && grep -qE 'libphp[^ ]*[.]so.*[(]deleted[)]' "$d/maps" 2>/dev/null && st="$l [libphp.so replaced]"
  [ -z "$st" ] && continue
  grep -qE 'docker|containerd|kubepods|lxc|libpod' "$d/cgroup" 2>/dev/null && continue
  u=$(grep -oE '[^/]+[.]service' "$d/cgroup" 2>/dev/null | head -1)
  echo "pid $p unit=${u:-none} $st"; sn=1; rc=$((rc|2))
  if [[ $u == *fpm*.service ]]; then units[$u]=1; else manual+=" $p(${u:-none})"; fi
done
[ $sn = 0 ] && echo none
if [ "$FIX" = 1 ] && [ -n "${!units[*]}" ]; then echo "restarting: ${!units[*]}"; systemctl restart "${!units[@]}"; fi
[ -n "$manual" ] && echo "MANUAL restart needed (web server):$manual"

echo "-- Docker containers with PHP (running only; read-only docker exec checks)"
PROBE_PHP='for b in php php-fpm /usr/local/bin/php /usr/local/sbin/php-fpm /usr/bin/php[0-9]* /usr/sbin/php-fpm[0-9]*; do command -v "$b" >/dev/null 2>&1 || [ -x "$b" ] || continue; v=$("$b" -n -v 2>/dev/null | head -1); echo "$v" | grep -qE "^PHP [0-9]" && { echo "$v"; break; }; done'
PROBE_CL='zcat /usr/share/doc/php*/changelog*.gz 2>/dev/null | grep -qE "CVE-2026-10961[89]" && echo Y; rpm -q --changelog php-cli php-fpm 2>/dev/null | grep -qE "CVE-2026-10961[89]" && echo Y'
PROBE_MP='apache2ctl -M 2>/dev/null || apachectl -M 2>/dev/null || httpd -M 2>/dev/null'
if [ "$DOCKER" = 1 ] && command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  total=0; withphp=0
  for c in $(docker ps -q); do
    total=$((total+1))
    pv=$(docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$c" | sed -n 's/^PHP_VERSION=//p' | head -1)
    if [ -z "$pv" ]; then
      pv=$(timeout 15 docker exec "$c" sh -c "$PROBE_PHP" 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    fi
    [ -z "$pv" ] && continue
    withphp=$((withphp+1))
    name=$(docker inspect -f '{{.Name}}' "$c"); name=${name#/}
    img=$(docker inspect -f '{{.Config.Image}}' "$c")
    iid=$(docker inspect -f '{{.Image}}' "$c")
    built=$(docker image inspect -f '{{.Created}}' "$iid" 2>/dev/null | cut -c1-10)
    s=EXPOSED; ver_ok "$pv" && s=PATCHED
    if [ "$s" = EXPOSED ]; then
      cl=$(timeout 15 docker exec "$c" sh -c "$PROBE_CL" 2>/dev/null)
      [[ $cl == *Y* ]] && s=PATCHED
    fi
    x=""
    timeout 15 docker exec "$c" sh -c "$PROBE_MP" 2>/dev/null | grep -qiE 'php[0-9]*_module' && x=" mod_php"
    [ "$s" = EXPOSED ] && { rc=$((rc|4)); cexp=1; }
    printf '%-26s %-36s php %-8s %-8s image built %s%s\n' "$name" "$img" "$pv" "$s" "${built:-?}" "$x"
  done
  [ $withphp = 0 ] && echo "none of $total running containers has PHP"
  [ $cexp = 1 ] && echo "FIX: pull/rebuild the image and recreate (e.g. docker compose pull && docker compose up -d --force-recreate). A plain restart keeps the old image."
else
  if [ "$DOCKER" = 0 ]; then echo "skipped (--no-docker)"
  elif ! command -v docker >/dev/null 2>&1; then echo "docker not installed - no containers to scan"
  else echo "WARNING: docker is installed but the daemon is not reachable (run as root or add the user to the docker group) - containers NOT scanned"; rc=$((rc|8)); fi
fi
