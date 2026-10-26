# php2shell — pure-HTTP PoC for CVE-2026-109618 / CVE-2026-109619

A lab reproduction of the PHP `session.upload_progress` memory-disclosure and code-execution chain on
`php:8.4.26-apache` (aarch64), using nothing but HTTP requests. No debugger is attached to the target,
nothing on the target reads `/proc`, and no file is placed on the target beforehand.

Four requests, two of which are arming steps:

```
A1  arm      header amplification OOMs at php_url_encode, leaving PS(id) dangling in a recycled chunk
B1  disclose rebuild that chunk with a forged zend_string: 819 200 bytes come back in Set-Cookie
    derive   turn the cookie into libphp / main chunk / S / hsv
A2  re-arm   OOM inside the multipart parser, leaving the stale zval slots in place
B2  execute  spray a fake zend_reference + a fake zend_array whose pDestructor is zif_system
```

Result on the tested target: `system()` runs as `www-data`.

## Status of this PoC

| what | result |
|---|---|
| single-worker baseline, fresh container per run | 3/3 |
| official MPM (`StartServers 5`, `MaxRequestWorkers 150`, nothing overridden) | 3/3 |
| arbitrary command (not a fixed payload) | verified (`uname -m`, hostname, `id -u`) |
| ASLR | fresh container gives a different `libphp`/`main`/`S`/`hsv` every time; addresses are recomputed from the disclosure on every run |
| **negative control, PHP 8.4.27** | **no arming, no disclosure, no execution — even with that build's true addresses**. The vulnerable code path is still reached; the difference is that this build charges its limit checks in 2 MiB units, so the failure never lands on the encoder ([details](docs/NEGATIVE_CONTROL_8.4.27.md#why-the-arming-shapes-do-not-transfer-measured)) |
| **PHP-FPM** | **does not transfer**: the arming fires identically, but FPM replaces the worker on a bailout, so no state survives ([details](docs/FPM.md)) |
| **other builds** | the arming signature (`4096` at the encoder) appears on **8.4.26 and 8.5.11**, and does not appear on **8.4.27, 8.5.12, 8.3.36 or 8.2.35** ([details](docs/VERSION_MATRIX.md)) |

Tested on **one** image and **one** configuration. See [Scope and limits](#scope-and-limits) before
reusing anything here.

## Requirements

- Linux host with Docker (the lab was run from a Kali box, aarch64).
- `python3` (standard library only) and `bash`.
- The target image, `php@sha256:60111400ff77bdc44fa79b4f072afe49a42abba71e0846ad496be4761dc9c11a`
  (`php:8.4.26-apache`, aarch64, trixie).
- Free TCP port `18110` on `127.0.0.1`.

## Quick start

```bash
cd POC_Final
bash lab/start_target.sh --single          # one worker: fastest way to see the whole chain
bash poc/chain.sh                          # defaults: id>/tmp/pwn.txt on the target
# -> proof:
# uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

The official-MPM variant needs the other children held busy, which `chain.sh --workers` does for you:

```bash
bash lab/start_target.sh                   # image defaults: StartServers 5 / MaxRequestWorkers 150
bash poc/chain.sh --workers 150
```

Or use the menu, which starts its own container per action:

```bash
bash poc/poc_menu.sh
#   1) full chain, official MPM (150 workers)
#   2) full chain, single-worker baseline
#   3) full chain with a custom command
#   4) disclosure only, ASLR check (N fresh containers)
```

## Layout

```
lab/
  start_target.sh              start/stop the target container (official image, php.ini-production copied in)
  apache-single-worker.conf    one-worker override for the baseline
  www/index.php                the whole docroot for the chain: <?php echo "OK\n"; ?>
  www/probe.php                diagnostic: what a request built (POST size, depth, peak memory)
lab-fpm/
  docker-compose.yml           nginx + php:8.4.26-fpm, one static worker (the "does it transfer?" lab)
  lab.ini, pool.conf, nginx.conf
  fpm_state.gdb                the state probe for a build with symbols
  www/probe.php                prints getmypid(), so "same worker" is measured, not assumed
poc/
  chain.sh                     A1 -> B1 -> addresses -> A2 -> B2, then reads the proof
  poc_menu.sh                  numbered runner (starts a container per action)
  a1_arm.py                    A1 arming request
  a1_probe.py                  cost of the exact arming body, measured at script entry (search aid)
  b1_forge.py                  B1 disclosure builder (--spec, --tag, --save-cookie)
  decode_leak_cookie.py        decoder for the disclosure cookie
  leak_addrs.py                cookie -> LIBPHP / MAIN / S / HSV / ZIF_SYSTEM
  a2_cheap_oom.py              A2 arming request
  mk_fake_ht.py                fake zend_array + execute_data + zend_string carrier
  b2_exec.py                   fake-reference spray and the trigger field
  hold_workers.py              occupies MaxRequestWorkers-1 children
  negative_control.sh          the paired control: chain must land on 8.4.26, must not on 8.4.27
gdb/                           calibration instruments (never used in a delivery run)
  reach.gdb                    is the encoder reached at all? (breakpoints on the two functions)
  oom_trace.gdb                what allocation fails, and where it is charged
docs/
  POC_CHAIN.md                 the chain, the address model, the runbook, the limits
  NEGATIVE_CONTROL_8.4.27.md   protocol, results, and what "no evidence" is defined to mean
  FPM.md                       why the chain is prefork-specific, measured against nginx + FPM
  VERSION_MATRIX.md            which builds still arm: the 4096 signature across six images, plus the
                               8.5.11 port attempt and what it takes
  B1_GATE.md                   23 iterations of the research log, including the retractions
  A1_CALIBRATION.md            where the arming OOM must land and why
  SID_ADOPTION.md              can the chain choose its own session id (stock ini)?
  SID_ADOPTION_MATRIX.md       the deterministic adoption matrix
HISTORY.md                     how the reproduction went, day by day
NOTICE.md                      provenance and licensing
```

## How the addresses are obtained

The leak is the only source. The disclosure window is 819 200 bytes starting at the stale session id,
and 900 nested POST arrays put real `zend_array` structures into the pages a partially-filled value
left free — their `pDestructor` is `zval_ptr_dtor`, so the window carries 876 copies of it. That is
enough to place libphp:

| value | relation | established by |
|---|---|---|
| `zval_ptr_dtor` | `libphp + 0x638120` | 876-copy cluster; gdb sees the same 876 in the chunk |
| `zif_system` | `libphp + 0x42CD70` | resolved from the image's symbol table |
| main chunk | disclosed chunk `+ 0x400000` | leak cluster compared with `alloc_globals->heap` in the same run |
| `S` (fake array) | main `+ 0xF8398` | layout constant of this image |
| `hsv` (stale zval) | main `+ 0x7D720` | layout constant of this image |

Two traps worth knowing before reading the code:

1. **The window must contain real HashTables.** A value that ends at the forged header fills the chunk
   up to page 0x137 and frees nothing; the window then holds chunk addresses only, which looks like a
   valid leak. The working spec (`G:511:0x137*14,G:400:0x137,X:900`) leaves 111 free pages for the
   arrays to land in.
2. **The cookie is `urlencode`, not `rawurlencode`.** Byte `0x20` travels as `+`, and
   `zval_ptr_dtor`'s low byte *is* 0x20, so `…8120` arrives as `…812b`. It is lossless (a literal
   `0x2b` is sent as `%2B`) but a decoder that ignores it sees no symbol at all.

`poc/leak_addrs.py` fails closed: if the window has no fingerprint cluster it exits non-zero and
`chain.sh` stops before A2/B2, rather than trying a guessed base.

## Scope and limits

**Verified:** the image digest above, aarch64, `php.ini-production` active, `memory_limit=128M`,
`display_errors=Off`, `session.upload_progress.cleanup=On`, Apache prefork (1 and 150 workers).

**Not verified:** other PHP patch levels &#8212; 8.4.27 was measured to fail, but only for the arming
shapes constructible here (see [docs/NEGATIVE_CONTROL_8.4.27.md](docs/NEGATIVE_CONTROL_8.4.27.md));
x86_64, opcache/JIT, distro PHP packages, other `memory_limit` values, other hosts.
The *method* transfers; the *constants* do not &#8212; a different build moves `zval_ptr_dtor`/`zif_system`,
and `hsv`/`S`/`--fillers` are layout constants of this image.

**PHP-FPM does not work, and cannot:** the arming request reaches the same one-page allocation failure
there, but FPM terminates the worker on a bailout and forks a fresh one, so the dangling state never
reaches a later request. Measured, with the lab and the logs in [docs/FPM.md](docs/FPM.md).

**Requirements on the target:** a prefork SAPI where the four requests reach the same child
(`MaxConnectionsPerChild > 0`, a graceful restart, or a process manager that recycles workers between
the steps breaks the chain), plus the ini settings listed above. Behind nginx, the default
`client_max_body_size` of 1 MiB also blocks the arming body with a 413 before PHP is reached.

**Fingerprint:** roughly 34 MB of request body over four requests, two to four seconds, and the child
segfaults after the command runs — the same destroy path that calls `pDestructor` then unwinds through
a fake array. This is a research PoC, not a quiet tool.

**Scope:** lab only. Do not point it at a system you do not own or have written permission to test.

## Calibrating another image

The `gdb/` instruments read engine state instead of inferring from responses, and they work on the
official image (its symbol table is enough; no debug build needed):

| instrument | answers |
|---|---|
| `chain_state.gdb` | libphp base, main chunk, `S`, `hsv`, and which `ps_globals` field points at them |
| `a2_state.gdb` | what A2 leaves behind, plus the two heap slots |
| `b_tail_live.gdb` | the chunk the disclosure encode actually reads (parks on `php_url_encode`) |
| `b_dtor_tag.gdb` | how the destructor pointers are stored, tagged or not |
| `b_tail_probe.gdb` | module pointers in the chunk after a request |
| `a1_id_state.gdb` | is the string under `PS(id)` still intact after the arming request |
| `b1_id_page.gdb` | the page `PS(id)` sits on, and which surrounding chunks carry the forged value |
| `b1_page_finder.gdb` | where the encoder actually reads from, on a build where the geometry is unknown |
| `delta_probe.gdb` | `libphp − heap` distance (recorded to show it is *not* a usable constant) |

```bash
sudo gdb -q -batch -p "$(sudo pgrep -P "$(docker inspect -f '{{.State.Pid}}' p2s-target)" | head -1)" \
     -x gdb/chain_state.gdb
```

## Credit

The bug class and the original pure-HTTP research are not ours. This repository is an independent
reproduction with our own tooling, written so that every claim can be re-run and checked; see
[NOTICE.md](NOTICE.md) for provenance and for what was deliberately left out.

## Licence

MIT, copyright 2026 **GG ADVANCED IT Security UG**. Full text in [LICENSE](LICENSE). Source files carry an
SPDX header; `docs/` and the top-level Markdown files are covered by the same grant.

Redistribution of the *prior work* referenced in [NOTICE.md](NOTICE.md) is not covered, because none of it
is included here.
