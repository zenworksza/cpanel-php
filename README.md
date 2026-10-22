Checking cPanel and CloudLinux servers for the PHP RCE flaws (CVE-2026-109618 / CVE-2026-109619)

On 21 Oct 2026 the PHP project released 8.2.35, 8.3.36, 8.4.27 and 8.5.12 to fix two critical unauthenticated remote code execution vulnerabilities (CVSS 9.2). Upstream says only an update fully fixes them, and no complete configuration workaround exists.

On cPanel and CloudLinux, checking a version number isn’t enough. Vendors backport fixes without changing the version, so a server can show 8.3.35 and still be patched. Installing the package also doesn’t restart PHP-FPM masters, so they can keep running the vulnerable binary in memory. We wrote a script to check all of this.

What the script does

Lists every EasyApache (ea-php) and CloudLinux (alt-php) package for the CLI, FPM, CGI, LiteSpeed and common components.
Marks each one PATCHED if its changelog names the CVEs, or if its version is at or above the upstream fix for 8.2 to 8.5. Anything else is EXPOSED.
Checks the /usr/bin/php wrapper by build date, because it carries no CVE changelog.
Reports pending updates and whether mod_php is loaded. Upstream rates mod_php the highest-risk SAPI.
Finds stale processes: PHP and web server processes still running a binary that has since been replaced.
Lists the accounts using any version marked EXPOSED or IGNORED, so you know who is affected before removing a version.
Exits with a bitmask code (1 = exposed packages, 2 = stale processes, 4 = accounts on an exposed version), so a fleet loop can alert on it.

What it changes

By default it only reads. --update runs the package update and then restarts active FPM units. --fix restarts only the FPM units that are stale. Apache and php-cgi are never restarted automatically, because that affects every site on the box.

Limitations

The changelog check depends on the vendor naming the CVE. A patched package that doesn’t name it will show EXPOSED, which is the safe failure.
The build-date check for /usr/bin/php is a heuristic.
Account counting uses selectorctl for alt-php and cPanel’s userdata files for ea-php. Verify the ea-php count against a version you know has accounts.
Retired versions such as PHP 5.1 get no fix at all. The script tells you who is on them, and removal is a separate step.
This is a verification tool, not a mitigation. Patch and restart first.
