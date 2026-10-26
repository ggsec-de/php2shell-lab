# Disclosure draft — var_destroy re-entry UAF (GH-24373) exploitability

To: security@php.net
Subject: GH-24373 follow-up: the re-entry UAF is a controlled pointer dereference on a stock build

---

Hello,

We reproduced the issue fixed by 08f4b64e0ae6 ("Fix GH-24373: serialize() context reused by destructors
during teardown") and ran one further measurement that may matter for how the fix is rolled out. We are
reporting it because it changes the practical severity, not because we have a new bug.

**Summary.** The UAF is not crash-only, and it does not need a sanitizer build or a swapped allocator. With
the default Zend MM on a stock release image, reclaiming the freed `var_entries` block with attacker-chosen
bytes turns the subsequent `R:` read into a dereference of a pointer we control:

```
php:8.5.12-cli (official image, default Zend MM, no special flags)

  reclaim length 3072..8160       ->  SIGSEGV, si_addr built from our filler
  reclaim length <=2048, >=8161   ->  survives
  100 consecutive runs at 8160    ->  100 crashes, 0 survivors
```

The 8160 boundary is the size of the freed entries block, so this is a reclaim and not a coincidence. The
faulting address is our own filler bytes: seven of the eight bytes are the `0x42` we wrote. The eighth byte
is `0x4a` and is constant across the three lengths we tested, so it is not our data and not the
`zend_string` length (which changes with the length); we have not established what it is, and we would
rather report it as an open detail than guess. Our reading of the consequence: an attacker-chosen 8-byte
value is used as a `zval*` and dereferenced, which is the primitive a full chain would build on.

**What we tested.**

| build | allocator | result |
| --- | --- | --- |
| 8.5.12, tagged source, ASAN | `USE_ZEND_ALLOC=0` | heap-use-after-free, `var_unserializer.c:906` |
| 8.2.35, tagged source, ASAN | `USE_ZEND_ALLOC=0` | heap-use-after-free |
| 8.2.34, tagged source, ASAN | `USE_ZEND_ALLOC=0` | heap-use-after-free |
| official images, **every release from 7.0.33 to 8.5.12**: 7.0.33, 7.1.33, 7.2.34, 7.3.33, 7.4.33, 8.0.30, 8.1.34, 8.2.34, 8.2.35, 8.3.36, 8.4.26, 8.4.27, 8.5.11, 8.5.12 (14 releases, 11 lines) | **default Zend MM** | SIGSEGV in every one |
| `php:5.6-cli` 5.6.40, trigger rewritten for 5.6 syntax | default Zend MM | survives |

The affected range we measured is therefore 7.0 through 8.5.12; 5.6 does not reproduce with the same shape.
Since the fix exists only on `master` and no 8.5.13 has shipped, **no released PHP contains it**.

Under gdb, the same probe with different fillers shows the address is ours:

```
filler B (0x42)    si_addr = 0x424242424242424a
filler C (0x43)    si_addr = 0x434343434343434b
0..255 pattern     si_addr = 0x0f0e0d0c0b0a0910    (R:1020 gives 0x0706050403020108)
```

Trigger shape, for reproduction: more than `VAR_ENTRIES_MAX` (1018) pushes so the entries are chained, plus
an object that reaches a `var_dtor` slot. A duplicate key does the ownership transfer:

```php
class Reclaim { public function __destruct() {
    $GLOBALS['buf'] = str_repeat('B', $GLOBALS['len']);   // reclaim
    @unserialize('R:1021;');                              // reads a zval* out of the reclaimed bytes
} }
$parts = [];
for ($k = 0; $k <= 1017; $k++) { $parts[] = "i:$k;i:1;"; }
$parts[] = 'i:9998;O:7:"Reclaim":0:{}';
$parts[] = 'i:9998;i:5;';
unserialize('a:1020:{' . implode('', $parts) . '}');
```

**Why we think this matters for the release plan.** The regression tests added in 08f4b64
(`gh24373.phpt`, `gh24373_unserialize.phpt`) are present on `master` but **not** in the `php-8.5.12` tag, so
"fixed in the next release" is accurate for 8.5. If the primitive is a controlled dereference, then 8.2, 8.3
and 8.4 users have no release to wait for, and the question is whether the fix should be backported to
those branches rather than waiting for them to pick up a later 8.5.

We would be glad to know:

1. whether the fix is planned for backport to the 8.2/8.3/8.4 branches, and on what timeline;
2. whether you would like the minimal probe script (it only reclaims and reads, it does not call anything);
3. whether you want us to hold our write-up until a release containing the fix is out.

**What we have not done.** We did not build an end-to-end exploit and we are not claiming one. A third party
has published claims of full RCE through this class (ACD421/PHP, "php2shell-zeros", zero4); we could
reproduce the memory error and the controlled pointer, but not their chain, and their own status document
records the same failure ("leak->write->call did NOT re-fire"). We are not publishing anything until a
patched release exists.

Happy to provide logs, the exact image digests, or to re-run anything you would like confirmed.

Regards,
GG ADVANCED IT Security UG
security contact: research@ggsec.de

---

## Operational notes before sending

- Attach: the probe script, the ASAN report, and the gdb `si_addr` transcript. Do not attach the whole lab.
- Keep the tone as above: measured, no CVSS number, no "0-day" framing.
- If they ask for the chain, the answer is the one already stated: we have not built it and do not intend to
  before a patched release.
- Record their reply here, including the backport decision, so the timeline in `README.md` and `NOTICE.md`
  can be updated with facts rather than assumptions.
