# Review of prior work: ACD421/PHP ("php2shell-zeros")

Two separate questions were asked about that repository: whether the NativePHP findings are real, and
whether the `var_destroy` re-entry UAF reproduces. They are answered from evidence, not from the
repository's own claims, and both answers are recorded here.

Nothing in this document is a weapon. The instrument is `poc/vd_reentry_gen.py`, which writes the smallest
script that makes the memory error visible under ASAN.

## 1. The NativePHP bridge findings: real, and fixed upstream within a day

The claim was an unauthenticated bridge (`POST /_native/api/call`) plus raw-path file operations and a
poisonable `unserialize()` lane. Checked against the framework source, not their lab:

| evidence | result |
| --- | --- |
| `NativePHP/mobile-air` `routes/api.php` | `Route::post('_native/api/call', NativeCallController::class)` — no middleware, exactly as claimed |
| `resources/.../FileFunctions.swift` on `main` | `confinementError(from:to:)` guard before both `moveItem` and `copyItem`, with `resolvingSymlinksInPath()`; Kotlin twin uses `canonicalPath` |
| `tests/Unit/FileFunctionsConfinementTest.php` | regression test whose comment names the attack: *"a file-exfil primitive (copy a secret into public/, read it back at /_assets/…)"* |
| **PR #609 "Harden the web-view-reachable bridge surface"** | merged **2026-10-25T15:49Z**, one day after publication |

The PR body is the strongest evidence, because it is upstream confirming the premises rather than a
researcher describing them:

> `routes/api.php` is registered with **no middleware (no CSRF, session or auth)** … That script can POST
> freely to `/_native/api/call` and `/_native/api/events`.
>
> The background runner **used to `unserialize()` whatever it found** in
> `storage/framework/async/payload/<id>.task`. Anything able to write that file could have the app run it.

So: the bridge findings were real, and the dangerous primitives were removed. Note what is **not**
established by any of this: the end-to-end RCE through NativePHP. Their own
`zero6_nativephp/NATIVEPHP_STATUS.md` says the leak→write→call chain "did **NOT** re-fire", and that the
lab is a "faithful mini-clone" rather than the framework. What they demonstrated is UAF, SIGSEGV,
controlled pointer (`0x42424242…`), file exfiltration and event forgery — not code execution. The README's
"9.8 RCE" line is ahead of its receipts; the status document is not.

Also worth recording: the framework findings depend on a *webview-content premise* (XSS, a bundled
third-party script, or `adb` webview debugging), which the PR states in the same words. It is a real
finding, not a no-premise remote.

## 2. The `var_destroy` re-entry UAF: reproduces, and is not in 8.5.12

Claim: a use-after-free in `unserialize()` reachable with plain attacker data, unpatched through 8.5.12.
Reproduced independently on this lab's aarch64 ASAN images with a trigger written here.

**The mechanism, from `ext/standard/var_unserializer.re`:** `php_unserialize_data` carries an embedded
`var_entries` of `VAR_ENTRIES_MAX` (1018) zvals; past that the entries are chained into a heap block.
`var_destroy` frees the chained blocks *first*, so `d->last` points into freed memory, and only then walks
the destructor slots calling `i_zval_ptr_dtor` unbracketed. A `__destruct` that calls `unserialize()`
therefore reuses the dying context and pushes through `d->last` into the freed block.

**The trigger needs two things,** both present in the published payload: more than 1018 pushes, and an
object that reaches a destructor slot — done with a duplicate key, which moves the first occurrence's
object into a `var_dtor` slot while the second occurrence becomes the array value.

Measured, `USE_ZEND_ALLOC=0` so that ASAN can see through the allocator:

| image | result |
| --- | --- |
| `php-asan:8.5.12` | **heap-use-after-free**, `var_unserializer.c:906` ← `var.c:1544` ← `zif_unserialize` ← destructor path |
| `php-asan:8.2.35` | **heap-use-after-free** |
| `php-asan:8.2.34` | **heap-use-after-free** |

The stack matches the published receipt line for line, including the 8160-byte freed region. So the
"var layer unchanged since 8.1" part of the claim is also supported by two extra version points we had.

**With Zend MM enabled the same script prints `SURVIVED`** — the UAF happens inside the Zend allocator, so
there is no crash and no ASAN report. That is the practical difference between the two runs, and it matters
for severity: on a stock build this is silent corruption unless the freed block is reused in a way that
matters.

**The fix is real and is not in 8.5.12:**

| check | result |
| --- | --- |
| `php/php-src` commit `08f4b64e0ae6` | "Fix GH-24373: serialize() context reused by destructors during teardown", 2026-10-22, touches `var.c` and `var_unserializer.re`, adds `gh24373.phpt` and `gh24373_unserialize.phpt` |
| tests present in tag `php-8.5.12` | **no** — 27 701 files, neither test |
| tests present on `master`, `PHP-8.5`, `PHP-8.4` | yes — the fix was merged to all three on 2026-10-22 |
| tests present on `PHP-8.3`, `PHP-8.2` | no |

So "not fixed in 8.5.12, fix ships in the next 8.5" is accurate, and 8.4 is patched on the branch too.
The repository also credits the prior reporter (`janhelke`, GH-24373) rather than claiming discovery,
which is the honest way round.

As of 2026-10-27 the publishing party has moved on from this finding: they now claim a public-URL RCE
with receipts and raised the CVSS to 9.8, and their newest material is an INI-parsing UAF
(`fa_jammy.sh`, "stage-2 INI-UAF pre-RINIT arm"), not the serializer. Their commit log also records that
the report went to `sec@php.net` **after** the public release.

## 2a. It is not crash-only: the pointer is controlled on a stock build

The published material stops at a controlled pointer under ASAN, where Zend's allocator is bypassed, and
their README's "9.8 RCE" line is not backed by a working chain. The question that decides the severity is
therefore: does the primitive survive on a **stock** build, with Zend MM active and nothing special set?

Measured with `poc/uaf_reclaim_probe_gen.py` on `php:8.5.12-cli` (official image, default allocator),
reclaiming the freed block with a string of controlled bytes and then reading a zval pointer out of it:

| reclaim length | result |
| --- | --- |
| 8100, 8130, 8150, 8159, **8160** | **SIGSEGV** |
| 8161, 8170, 8200, 9000 | survives |

The boundary at 8160 is the size of the freed entries block, which is what makes this a reclaim rather
than a coincidence. And the fault is not wild:

```
Program received signal SIGSEGV
$1 = 0x424242424242424a          <- our 'B' bytes
#1  php_var_unserialize ()
```

`si_addr` is attacker-chosen. The trailing `4a` is the length byte of the `zend_string` header, i.e. the
read starts two bytes past our data - a detail for whoever builds the next step.

So the primitive on a stock build is "an 8-byte value we choose, used as a `zval*` and dereferenced". That
is the same primitive our own chain uses, and it is enough for a full chain in principle: aim it at a fake
zval inside a buffer we already control, let the destructor slot resolve to a call.

**This changes the severity argument, and that is the part worth reporting.** "Not fixed in 8.5.12, fix
ships in 8.5.13" reads as a reason to wait for the next release. A controlled dereference on the default
allocator reads as a reason to backport to every maintained branch now, because 8.2/8.3/8.4 users have no
8.5.13 to wait for.

We stop here deliberately: the remaining step is assembling leak + fake zval + call into a working weapon,
and that is not something to have lying around while every released PHP is unpatched. The measurement above
is what a vendor needs to prioritise; the exploit is not.

## 3. What this changes about our own work

Nothing. Our chain is the `session.upload_progress` stale-identifier bug (CVE-2026-109618/109619); theirs is
the var-layer destroy walk. Independent failure classes with independent fixes, and the version matrix in
`docs/VERSION_MATRIX.md` says nothing about theirs.

Two incidental corroborations are worth keeping, because they came from an independent source:

- they state that NativePHP's bundled PHP 8.4.27 and 8.3.36 carry the October-2026 patch that fixed
  CVE-2026-109618/109619 — which is exactly what our `4096` signature shows for both;
- they state that the embed SAPI parses multipart in PHP userspace, so there is "no rfc1867 lane at all" —
  the same conclusion our FPM work reached from the other direction.

## 4. A lesson about rewritten triggers

The first run of our own generator said `SURVIVED` on every image, and the reason was ours: the payload
declared `O:1:"D"` while the script defined class `Reentry`, so the object decoded as
`__PHP_Incomplete_Class` and its destructor never ran. A negative produced by a *rewritten* trigger is
worth nothing until the rewrite is faithful — and the cheapest way to find out is to run the original next
to it. That check is now the first step of any "does their claim hold" run here.

## Reproduce

```bash
python3 poc/vd_reentry_gen.py                       # writes vd_reentry_generated.php
docker run --rm -v "$PWD:/w:ro" -e USE_ZEND_ALLOC=0 -e ASAN_OPTIONS=detect_leaks=0 \
  php-asan:8.5.12 php /w/vd_reentry_generated.php
```

Drop `USE_ZEND_ALLOC=0` to see the silent variant.
