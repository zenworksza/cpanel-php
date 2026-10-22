# PHP CVE-2026-109618 / CVE-2026-109619 check scripts

Two scripts that check a server for the PHP remote code execution flaws disclosed on 21 Oct 2026 ([advisory](https://www.php.net/archive/2026.php#2026-10-21-5)). Both are bash, and both only read by default.

Upstream fixed these in PHP 8.2.35, 8.3.36, 8.4.27 and 8.5.12 and says only an update fully fixes them. These scripts verify that you are patched. They are not a mitigation.

## Why not just check `php -v`?

- Vendors (cPanel/CloudLinux, Debian, Ubuntu, RHEL) backport the fix without changing the version number, so a patched server can still report `8.3.35`.
- Installing the package does not restart running PHP-FPM masters, so they can keep serving the vulnerable binary from memory.

The scripts check package changelogs for the CVE IDs and look for processes still running a replaced binary.

| Script | For | Tested on |
|---|---|---|
| `cpanel-php-cve.sh` | cPanel/WHM with EasyApache (`ea-php`) and CloudLinux (`alt-php`) | AlmaLinux 8.10 + cPanel + CloudLinux |
| `non-cpanel.sh` | Debian/Ubuntu, RHEL-family, and Docker hosts | Ubuntu 24.04 (host packages) |

## Usage

```bash
chmod +x cpanel-php-cve.sh non-cpanel.sh
./cpanel-php-cve.sh            # check only
./cpanel-php-cve.sh --update   # update PHP packages, restart active FPM, then check
./cpanel-php-cve.sh --fix      # restart only stale FPM units

./non-cpanel.sh                # check only
./non-cpanel.sh --update       # upgrade host PHP packages, restart active FPM, then check
./non-cpanel.sh --fix          # restart only stale FPM units
./non-cpanel.sh --no-docker    # skip the container scan
```

Run as root. Apache and `php-cgi` are never restarted automatically, since that affects every site on the box. Restarting FPM briefly interrupts requests, so roll out in batches.

## `cpanel-php-cve.sh`

- Checks every `ea-php` and `alt-php` package (CLI, FPM, CGI, LiteSpeed, common). Each is `PATCHED` or `EXPOSED`.
- Checks `/usr/bin/php`, which has no CVE changelog, by build date.
- Reports pending updates, `mod_php`, and stale processes.
- Lists accounts using any `EXPOSED` or `IGNORED` version. For `alt-php` this is accounts assigned in CloudLinux Selector, which can be more than what MultiPHP shows running.
- `alt-php-internal` is ignored by default (CloudLinux tooling, not customer runtime). Set `IGNORE=none` to include it.

Exit code (bitmask): `1` exposed packages, `2` stale processes, `4` accounts on an exposed version.

## `non-cpanel.sh`

- Host packages: Debian/Ubuntu (`php8.x-*`, `libapache2-mod-php`) and RHEL-family (`php-*`, Remi). Checks the distro changelog for the CVEs, then falls back to a version comparison.
- PHP binaries not owned by a package: version check only, so backports are invisible.
- Stale processes, including Apache with a replaced `libphp.so`.
- Running Docker containers: reads the PHP version, flags `mod_php` images, and shows the image build date. A restart does not patch a container. Pull or rebuild the image and recreate it (`docker compose build --pull --no-cache <service>` for locally built images).

Exit code (bitmask): `1` exposed host packages or binaries, `2` stale processes, `4` exposed containers, `8` Docker installed but not scanned (daemon unreachable).

## Limitations

- The changelog check relies on the vendor naming the CVE. A patched package that does not will show `EXPOSED`, the safe failure.
- PHP 8.1 and older have no upstream fix. They show `PATCHED` only if the vendor backported it.
- `non-cpanel.sh`: container scanning, the RHEL/Remi path, and `--update` with real updates pending are untested. FrankenPHP and LiteSpeed are not checked.
- Only running containers are scanned, not stopped containers or unused images.
- Verification only. Patch and restart first.
