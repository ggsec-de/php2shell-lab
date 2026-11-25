Subject: GH-24373 follow-up: the re-entry UAF is a controlled pointer dereference on released builds

To: security@php.net
Sent: 2026-10-26

---

Hello,

We reproduced the issue fixed by 08f4b64e0ae6 ("Fix GH-24373: serialize() context reused by destructors
during teardown") and ran one measurement beyond the ASAN report that we think changes how the fix should be
rolled out. We are not reporting a new bug.

**1. The primitive is live on released builds, with the default allocator.**

On official images, default Zend MM, no special flags, reclaiming the freed `var_entries` block with
attacker-chosen bytes turns the subsequent `R:` read into a dereference of a pointer we control:

```
php:8.5.12-cli, len 3072..8160        ->  SIGSEGV, si_addr built from our filler
               len <=2048, >=8161     ->  survives
               100 runs at 8160       ->  100 crashes, 0 survivors
```

Under gdb, same probe, different fillers:

```
filler B (0x42)          si_addr = 0x424242424242424a
filler C (0x43)          si_addr = 0x434343434343434b
0..255 pattern, R:1021   si_addr = 0x0f0e0d0c0b0a0910
0..255 pattern, R:1020   si_addr = 0x0706050403020108
```

The address follows our data, and the reference index moves the read window by exactly eight bytes per
step (`R:1020` and `R:1021` differ by `0x0808080808080808`). It is an attacker-chosen 8-byte value used as a
`zval*`, deterministically, on the default allocator.

**2. Affected range, as measured (not inferred).**

Fourteen releases across eleven development lines reproduce with the same probe:

```
7.0.33  7.1.33  7.2.34  7.3.33  7.4.33  8.0.30  8.1.34
8.2.34  8.2.35  8.3.36  8.4.26  8.4.27  8.5.11  8.5.12
```

`5.6.40` does not reproduce with the same shape (trigger rewritten for 5.6 syntax, sanity-checked against
7.4 in the same run). One image per line plus a second point on 8.2 and 8.4, so the honest claim is "every
release tested", not "every patch level".

**3. Why we are writing at all.**

The regression tests added in 08f4b64 (`gh24373.phpt`, `gh24373_unserialize.phpt`) are present on `master`
but not in the `php-8.5.12` tag, and no 8.5.13 exists yet. If the primitive is a controlled dereference, then
users of 7.4 / 8.0 / 8.1 / 8.2 / 8.3 / 8.4 have no release to wait for, and that is a different scheduling
question than "fixed in the next 8.5".

Our questions:

1. is the fix planned for backport to those branches, and on what timeline?
2. would you like the probe scripts and raw outputs (attached) in another form?
3. do you prefer that we hold our write-up until a release containing the fix ships? Our default is to hold,
   and we will not publish before that unless you tell us otherwise.

**4. What we did not do.**

We did not build an end-to-end exploit and we do not claim one. A third party (ACD421/PHP, folder
`zero4_var_destroy_uaf`) has published claims of full RCE for this class; we could reproduce the memory error
and the controlled pointer, but not their chain, and their own status document records the same failure
("leak->write->call did NOT re-fire").

**Attachments**

| file | what it is |
| --- | --- |
| `probe_stock.php` | the stock-build probe: reclaim + `R:` read, no call |
| `probe_asan.php` | the same trigger for the sanitizer build |
| `results_versions.txt` | the 15-image version matrix, exit codes as measured |
| `results_reliability.txt` | 100 consecutive runs at length 8160 |
| `results_si_addr.txt` | gdb `si_addr` for five filler/index combinations |
| `asan_report.txt` | full ASAN report on 8.5.12 with `USE_ZEND_ALLOC=0` |

Regards,
GG ADVANCED IT Security UG
research@ggsec.de

---

## Sent 2026-10-26

- Six files from `attachments/`, nothing else from the lab.

Still standing:

- If they ask for a PoC that calls something: we have not built one and do not intend to before a patched
  release; say so plainly rather than implying it exists.
- Record the reply in `docs/VD_REENTRY_FULL.md` (backport decision, timeline) and in the tracking table in
  `docs/DISCLOSURE_VD_REENTRY.md`.

---

## Follow-up, 2026-11-25

The 19 Nov 2026 security releases now exist (8.2.36, 8.3.37, 8.4.28, 8.5.13) and all four contain
`08f4b64`, so "no 8.5.13 exists yet" in the text above is historical. The affected range for released
builds before that batch remains 7.0.33 - 8.5.12. The rest of the report still stands.
