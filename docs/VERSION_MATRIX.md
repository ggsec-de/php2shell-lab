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

**The disclosure does not transfer.** With a spec that works on 8.4.26 the 8.5.11 target answers
`200 OK` with a small body and no `Set-Cookie`, and sweeping the header page across `0x135..0x138` changes
nothing. The request does not even fail: it completes, which says the forged header is not being reached at
that point. Why, and where the value does land, is the open question - see the next subsection, which also
records two harness mistakes that made earlier answers to it meaningless.

### What is actually established, with the harness corrected

Two harness mistakes invalidated earlier readings in this section, and both are worth recording because
they look like results:

1. **The arming body's shape matters.** `a1_arm.py` with only `--sid-hex` still produces the `4096`
   refusal, but it leaves a different heap layout. Every earlier "no response / SIGSEGV" row in this
   section, including the `ps_close_files` stacks, was measured in that wrong state. The chain's own
   arming is `--big 78 --query-n 5 --query-len 1`, and every row below uses it.
2. **Attaching a debugger perturbs the request.** Catching SIGSEGV with gdb attached produced
   byte-identical frames on both builds, while 8.4.26 returns a 1.6 MB cookie when nothing is attached.
   Any stack obtained that way is evidence about the debugger, not about the build.

With the harness corrected - single worker, stock ini, one fresh container per row:

| case | 8.4.26 | 8.5.11 |
| --- | --- | --- |
| A1 with the chain shape | `4096` refusal | `4096` refusal |
| `PS(id)` after A1 | page `0x137`, `len=0x20`, 32 hex chars, intact | page `0x136`, `len=0x20`, 32 hex chars, intact |
| B1 with `p` = that page | **`200 OK`, cookie 1 679 452 chars** | `200 OK`, 195 bytes, **no cookie** |
| B1 with `p` swept `0x135..0x138` | not needed (the page above works) | no disclosure at any of the four |
| segfaults | 0 | 0 |

So the summary for 8.5.11 is narrower than an earlier draft of this section claimed:

- the arming step **is** equivalent to 8.4.26: same refusal, same intact stale string, one page lower in
  the chunk;
- the disclosure step produces **nothing**, and does not crash. The request completes normally with a small
  body, which means the forged header is not reached at that point in the request;
- the earlier claims here about a `ps_close_files` obstacle, and about the forge "landing" with `p=0x136`,
  were artefacts of the simplified arming and are withdrawn.

What is left is a well-defined question rather than a mystery: **at which page, and at which point in the
request, does the 511-page value land on 8.5.11**. The instrument for it is a breakpoint on
`php_url_encode` that only counts hits and prints `$x0`/`$x1` - no memory scan, so the worker is stopped
for microseconds - combined with a page sweep across the whole chunk instead of four points.

### The encoder is never called on 8.5.11

Counting breakpoint hits without stopping the worker (`gdb/b1_hits.gdb`: `stop()` returns `False`, so the
worker is held for microseconds) settles where the two builds diverge, and it is not the page:

| build | `php_url_encode` hits during the disclosure request | what it read | cookie |
| --- | --- | --- | --- |
| 8.4.26 | **1** | `buf=...37018  len=0xc8000` - our forged header | 1 685 560 chars |
| 8.5.11 | **0** | - | none |

So on 8.5.11 the session cookie is never encoded, which means the session is not initialised-as-sending in
that request at all. A page sweep cannot fix a call that never happens, and the earlier sweeps over
`0x135..0x138` were measuring the wrong thing entirely.

**What that leaves open, precisely:** why `php_session_send_cookie` is not reached on 8.5.11 while the same
body reaches it on 8.4.26. Two candidate explanations, and both need an instrument this image does not
provide:

- `php_ps_globals` changed layout between the builds, so the flag that means "send the cookie" is at a
  different offset - and the arming, which leaves that flag set on 8.4.26, no longer does so on 8.5.11;
- the session-start path itself changed (the upload-progress callback ordering), so the request never
  enters the code that sends the cookie.

Reading the layout means DWARF, and these images ship symbols without debug info: `ptype ps_globals`
returns nothing, which is why every offset in this document was obtained by resolving addresses and
reading memory instead. Two ways forward, in ascending cost: diff `ext/session` between 8.4.26 and 8.5.11
for the send-cookie and rfc1867-callback paths, or build 8.5.11 with `-g` (the FPM debug build recipe in
`lab-fpm/` is reusable) and read the struct layout directly.

**Also measured:** `main - idchunk = 0x1000000` on 8.5.11 (against `0x400000` on 8.4.26). That number turns
the disclosed chunk into the main chunk, so it needs confirming over several fresh containers once a leak
exists.


## Limits

- The signature is not the chain. A `4096` says the arming step is reachable; it does not by itself
  prove disclosure or execution, which need addresses recalibrated for that build. The full chain was
  verified end-to-end on 8.4.26 (3/3) and, by the separate PoC, on 8.5.11 (3/3).
- Stock `php:*-apache` images only, aarch64, single Apache child. No FPM row here (FPM cannot carry the
  state across requests at all, see [FPM.md](FPM.md)), no x86_64, no distro packages, no opcache.
- "No OOM" is a statement about these three shapes and this ini. It is not a proof that no body
  exhausting a page can be built for these builds; it is the same class of evidence as the negative
  control, one instrument stronger because the positive control is on a different branch.
