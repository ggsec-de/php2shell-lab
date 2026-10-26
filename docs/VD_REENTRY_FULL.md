# var_destroy re-entry UAF — full technical record

Everything we know about the bug fixed by `08f4b64e0ae6` (GH-24373), written so that someone can check it
without re-running our lab. Every claim is marked as **measured**, **source-read**, or **unknown**, because
the difference matters when deciding how much to trust a disclosure.

The short version: the memory error is real and reproduces on 8.5.12, 8.2.35 and 8.2.34; on a stock build
with the default allocator it produces a dereference of an attacker-chosen pointer; we did not build a chain
and we are not claiming RCE.

---

## 1. The bug — source-read

`ext/standard/var_unserializer.re` (the `.c` is generated). Three facts compose into the bug, and all three
have to hold at once:

**1.1 The entries array is chained past `VAR_ENTRIES_MAX`.** `php_unserialize_data` carries an embedded
`var_entries` with room for `VAR_ENTRIES_MAX` (1018) `zval*`. Every decoded value pushes into it; once it is
full, a further block is allocated and linked (8160 bytes on 64-bit: a header plus 1018 pointers).

**1.2 `var_destroy` frees the chained blocks before walking the destructor slots.** The loop frees the chain
and leaves `d->last` pointing into memory it has just released. Only afterwards does the dtor-slot walk run
`i_zval_ptr_dtor` per slot, and that walk is **not bracketed**: a slot holding the last reference to an
object runs `__destruct` with `BG(serialize_lock) == 0` and `BG(unserialize).data` still pointing at the
dying context.

**1.3 The context is freed last.** `php_var_unserialize_destroy` runs `var_destroy` and `efree(d)` *before*
decrementing `BG(unserialize).level`, so throughout the walk `level == 1 && data == d`. A re-entrant
`unserialize()` therefore takes the reuse branch in `php_var_unserialize_init` and continues with the dying
context.

Consequence: the first value decoded by the re-entrant call executes `var_push` with
`var_hash = (*var_hashx)->last` — the freed block — so it reads `used_slots` and writes `data[used_slots]`
through freed memory. An `R:n` reference instead takes `var_access`, walking the freed `.next` chain and
returning `data[id]` as a `zval*`.

**Line numbers** quoted by the publishing party: `var_destroy` at `.c:242`, the dtor slot at `.c:319`,
`php_var_unserialize_destroy` at `.c:91`, `php_var_unserialize_init` reuse branch at `.c:66`, `var_push` at
`.c:143`, `var_access` at `.c:231`, and the faulting read at `var_unserializer.c:906`. We confirmed the
stack shape (`906` ← `var.c:1544` ← `zif_unserialize` ← destructor path) but not every line number.

## 2. The trigger — measured

Two ingredients, both necessary:

- **more than 1018 pushes**, so the entries block is chained and `d->last` points at a freed block;
- **an object that reaches a `var_dtor` slot**, so its `__destruct` runs inside the walk. The trick used by
  the publishing party is a duplicate key: the object is moved into a dtor slot while the second occurrence
  becomes the array value.

```php
class Reclaim {
    public function __destruct() {
        $GLOBALS['buf'] = str_repeat('B', $GLOBALS['len']);   // reclaim attempt
        @unserialize('R:1021;');                              // read a zval* out of reclaimed bytes
    }
}
$parts = [];
for ($k = 0; $k <= 1017; $k++) { $parts[] = "i:$k;i:1;"; }   // 1018 elements = 2036 pushes
$parts[] = 'i:9998;O:7:"Reclaim":0:{}';                       // the object ...
$parts[] = 'i:9998;i:5;';                                     // ... duplicate key moves it to a dtor slot
unserialize('a:1020:{' . implode('', $parts) . '}');
```

**A trap that cost us a run:** the class name in the payload must match the class in the script. Our first
generator declared `O:1:"D"` against a class named `Reentry`, so the object decoded as
`__PHP_Incomplete_Class`, the destructor never ran, and every image "survived". A negative from a rewritten
trigger means nothing until the original is run next to it.

## 3. Reproduction under ASAN — measured

Images built from tagged source with AddressSanitizer; `USE_ZEND_ALLOC=0` so that `efree_size` reaches
`free()` and ASAN can poison the region.

| image (aarch64) | allocator | result |
| --- | --- | --- |
| `php-asan:8.5.12` | `USE_ZEND_ALLOC=0` | heap-use-after-free, `var_unserializer.c:906`, 8160-byte freed region |
| `php-asan:8.2.35` | `USE_ZEND_ALLOC=0` | heap-use-after-free |
| `php-asan:8.2.34` | `USE_ZEND_ALLOC=0` | heap-use-after-free |

And the same probe on stock images, one run each, which is the measurement that matters for the affected
range because it uses the default allocator:

| stock image | PHP | result at length 8160 |
| --- | --- | --- |
| `php:5.6-cli` | 5.6.40 | **survives** (5.6-compatible trigger, sanity-checked against 7.4) |
| `php:7.0-cli` | 7.0.33 | SIGSEGV |
| `php:7.1-cli` | 7.1.33 | SIGSEGV |
| `php:7.2-cli` | 7.2.34 | SIGSEGV |
| `php:7.3-cli` | 7.3.33 | SIGSEGV |
| `php:7.4-cli` | 7.4.33 | SIGSEGV |
| `php:8.0-cli` | 8.0.30 | SIGSEGV |
| `php:8.1-cli` | 8.1.34 | SIGSEGV |
| `php:8.2.34-cli` | 8.2.34 | SIGSEGV |
| `php:8.2.35-cli` | 8.2.35 | SIGSEGV |
| `php:8.3.36-cli` | 8.3.36 | SIGSEGV |
| `php:8.4.26-apache` | 8.4.26 | SIGSEGV |
| `php:8.4.27-apache` | 8.4.27 | SIGSEGV |
| `php:8.5.11-apache` | 8.5.11 | SIGSEGV |
| `php:8.5.12-cli` | 8.5.12 | SIGSEGV |

**Fourteen releases across eleven development lines**, from 7.0.33 to 8.5.12, all crashing with the same
probe at the same length. **5.6.40 is the one build that survives**, measured with a trigger rewritten for
5.6 syntax and sanity-checked against 7.4, so the lower bound of the affected range sits between 5.6 and 7.0.

Caveats on the range, stated plainly: one image per line (the latest patch of each), plus a second point on
8.2 (8.2.34) and on 8.4 (8.4.26). Intermediate patch levels were not sampled, so the honest claim is "every
release we tested from 7.0 to 8.5.12", not "every patch level since 7.0".

The stack matches the published receipt: read in `php_var_unserialize` ← `php_unserialize_with_options`
(`var.c:1544`) ← `zif_unserialize` ← `zend_objects_destroy_object` ← `rc_dtor_func` ← `i_zval_ptr_dtor`
← `var_destroy` (`var_unserializer.c:319`) ← `php_var_unserialize_destroy` (`:94`).

**With Zend MM enabled the same script prints `SURVIVED`** and ASAN reports nothing — the UAF happens
inside Zend's allocator, invisible to ASAN. This is why an ASAN-only receipt does not settle the question
that follows.

## 4. The same script on a stock build — measured

`php:8.5.12-cli` (official image, default Zend MM, no flags). The destructor allocates a string of
controlled bytes to reclaim the freed block, then reads a `zval*` out of it with `R:<n>`.

### 4.1 Which reclaim lengths work

| reclaim length | result |
| --- | --- |
| 512, 1024, 2048 | survives |
| **3072, 4000, 6000, 7000, 8000, 8100, 8150, 8158, 8159, 8160** | **SIGSEGV** |
| 8161, 8162, 8165, 9000 | survives |

The window is `3072..8160`, and its edges follow Zend MM's size classes: at or below 3072 an allocation
comes from the small bins, in a different part of the heap, so it cannot take the freed block; from 3073 up
allocations are page-based and one of them fits inside the freed 2-page (8192-byte) run; at 8161 the request
needs a third page and no longer fits. *(Inference from the boundary; the bin mechanics were not traced.)*

### 4.2 Reliability

100 runs at length 8160, fresh process each time:

```
crashes=100  survived=0
```

Not a race. This is deterministic on this build.

### 4.3 The pointer is ours

| run | `si_addr` |
| --- | --- |
| filler `B` (0x42), `R:1021` | `0x424242424242424a` |
| filler `C` (0x43), `R:1021` | `0x434343434343434b` |
| filler `0..255` pattern, `R:1021` | `0x0f0e0d0c0b0a0910` |
| filler `0..255` pattern, `R:1020` | `0x0706050403020108` |
| filler `0..255` pattern, `R:1000` | survives |

Three facts fall out of that table:

- **the filler propagates**: `0x42` and `0x43` produce addresses built from `0x42` and `0x43`;
- **the read position is ours**: the positional pattern reconstructs the bytes, so the value is read out of
  the buffer we allocated, not out of stale memory;
- **the reference index selects the window**: `R:1020` and `R:1021` differ by `0x0808080808080808`, i.e.
  exactly one step of eight bytes in the pattern. `R:1000` survives, so not every index lands on a
  non-canonical value - the index matters.

**Open detail, stated rather than glossed:** with a constant filler seven of the eight bytes are the filler
and the eighth is `filler + 8` (`0x42 -> 0x4a`, `0x43 -> 0x4b`); with the pattern the eight bytes are not a
simple consecutive window either. The composition of that one byte is unresolved. It does not change the
conclusion - the pointer is dominated by data we choose and changes when we change it - but anyone building
on this needs to know the byte is not free.

**What this is:** an attacker-chosen 8-byte value dereferenced as a `zval*`, on the default allocator, in a
deterministic way. **What it is not:** a chain. There is no leak here, no fake zval, and no call.

## 5. Fix status — measured

| check | result |
| --- | --- |
| `php/php-src` commit `08f4b64e0ae6` | "Fix GH-24373: serialize() context reused by destructors during teardown", 2026-10-22 |
| files touched | `ext/standard/var.c`, `ext/standard/var_unserializer.re`, `NEWS` |
| tests added | `ext/standard/tests/serialize/gh24373.phpt`, `gh24373_unserialize.phpt` |
| tests present in tag `php-8.5.12` | **no** — 27 701 files in the tag, neither test |
| tests present on `master` | yes |
| `php-8.5.13` tag | does not exist yet |
| reported to `security@php.net` | 2026-10-26, no reply yet |

So "not fixed in 8.5.12" is accurate, and "ships in 8.5.13" is a plan rather than a fact. Nothing here says
whether the fix is intended for the 8.2/8.3/8.4 branches, which is the question we put to the PHP team on
2026-10-26; the reply and the resulting backport position belong in this table, and `README.md` and
`NOTICE.md` should quote it rather than guess.

## 6. Prior art and what the publishing party did and did not show

- **Original report:** GH-24373 (credited as `janhelke`), fix two days before the public write-up.
- **Publication:** ACD421/PHP, folder `zero4_var_destroy_uaf`, 2026-10-24. Their README lists the finding at
  "CVSS 9.8, remote via `unserialize()`".
- **What they demonstrated:** ASAN UAF, glibc SIGSEGV, a controlled pointer
  (`0x4242424242424242`), and — through their NativePHP lane — file exfiltration and event forgery.
- **What they did not:** a working end-to-end chain. Their own `NATIVEPHP_STATUS.md` says the
  leak→write→call chain "did **NOT** re-fire", and their lab is a "faithful mini-clone" of the framework.
  Their failure mode was the leak ("leak oracle returns 0x0"), not the memory primitive.

Their severity framing is therefore ahead of their receipts, while the bug itself is real. Both halves of
that sentence matter.

## 7. What a chain would need — analysis only

For orientation, not a plan to execute:

1. **A reclaim that lands deterministically** at the right offset under Zend MM across runs (section 4 shows
   it lands at one length on one run; the offset within the block is the open question).
2. **A fake zval** at a known address inside a buffer whose contents we control — the usual way is to place
   it in a string we already hold, then point the forged `zval*` at it. This needs the buffer's address,
   which is step 3.
3. **An address leak.** Their chain died here. Reading through the same slot with `R:n` can return heap
   pointers; whether that is stable enough depends on the reclaim layout. Our own work on a different bug
   shows the technique is viable when the dangling slot can be read repeatedly.
4. **A call target**: a destructor slot resolving to something like `zif_system`, with the argument taken
   from a controlled string. Per-build offsets, resolvable from the image's own symbol table.

None of this is done. The reason is not capability but timing: every released PHP is affected and no
patched release exists, so a working chain today has no defensive use that the crash and the controlled
pointer do not already provide.

## 8. What we would still measure, if asked

- **Reliability:** 100 runs at length 8160 on a stock build, count crashes, confirm the address is identical.
- **The `0x4a` byte:** dump the eight bytes at the faulting read's source address and identify the offset.
- **Zend MM mechanics:** which bin the 8160-byte block belongs to, and whether a string of that size is the
  only allocation that reclaims it (a size sweep already shows 8161+ no longer reclaims).
- **8.4/8.3:** ASAN builds of those branches, to state the affected range with measurements rather than
  inference from 8.2.34/8.2.35 and 8.5.12.

## 9. Our own measurement limits

- ASAN images are **aarch64**; the stock run is `php:8.5.12-cli` **aarch64**. Nothing here is x86-64.
- The stock sweep is one run per length; no reliability figure.
- We did not inspect `var.c` for a second reachable path into the same walk — we confirmed the one the
  publication describes.
- We did not test whether `allowed_classes` or an application-side `unserialize` wrapper changes anything;
  the trigger assumes a plain `unserialize()` on attacker data, which is the premise the publication states.

## Reproduce

```bash
python3 poc/vd_reentry_gen.py          # ASAN variant: writes vd_reentry_generated.php
python3 poc/uaf_reclaim_probe_gen.py   # stock variant: writes uaf_reclaim_probe.php

# ASAN, allocator bypassed
docker run --rm -v "$PWD:/w:ro" -e USE_ZEND_ALLOC=0 -e ASAN_OPTIONS=detect_leaks=0 \
  php-asan:8.5.12 php /w/vd_reentry_generated.php

# stock, default allocator
docker run --rm -v "$PWD:/w:ro" php:8.5.12-cli php /w/uaf_reclaim_probe.php 8160
```
