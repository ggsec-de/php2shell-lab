# Provenance and licensing

## What this repository contains

Everything under `poc/`, `lab/`, `lab-fpm/`, `gdb/` and `docs/` was written by GG Advanced IT Security while
reproducing the chain, and is released under the MIT licence (see the licence section below).

## What it does **not** contain, and why

Two directories from the private lab were deliberately left out:

| left out | why |
|---|---|
| `fake_exploits/` (four third-party exploit repositories, ~34 MB) | no licence file upstream, therefore no grant of rights. They were used as a black-box oracle during the work and are not redistributed here. |
| `reference/phpcve-lab-tools/` (a vendored copy of another researcher's tools) | same reason — upstream publishes no licence. The tools were used to pin the geometry; all numbers derived from them were re-measured with our own instruments and are recorded in `docs/`. |

The obvious consequence, stated plainly: **this repository cannot be run as a drop-in replacement for
those tools.** It can be run end to end on its own (`lab/start_target.sh` + `poc/chain.sh`). If you want
the oracle material, fetch it from upstream and respect its terms — do not expect it here.

## Prior work

The bug class, the original pure-HTTP research, and the first public write-ups are not ours. This work
started from another researcher's published results and independently rebuilt the chain with our own
tooling — every offset, every page number and every allocation size in `docs/` was re-measured on this
image, because a number copied from a different build only looks like knowledge.

If you are the author of upstream material referenced in `docs/` and want a correction or a link
changed, open an issue.

## Offsets are image-specific

Every offset in `docs/` (`zval_ptr_dtor = libphp+0x638120`, `zif_system = libphp+0x42CD70`, `S`, `hsv`)
belongs to one build:

```
php@sha256:60111400ff77bdc44fa79b4f072afe49a42abba71e0846ad496be4761dc9c11a   (php:8.4.26-apache, aarch64)
```

They are facts about that binary, not about PHP in general. Pinning the digest in `lab/start_target.sh`
is there to keep that statement true over time.

## Licence

**MIT**, copyright 2026 GG ADVANCED IT Security UG. The full text is in [LICENSE](LICENSE).

Everything under `poc/`, `lab/`, `lab-fpm/`, `gdb/`, `docs/` and the top-level Markdown files was written
by us, so the whole repository is covered by that grant. Individual source files carry an SPDX header:

```
SPDX-License-Identifier: MIT
Copyright (c) 2026 GG ADVANCED IT Security UG
```

The third-party material described above is **not** part of this grant, because it is not in this
repository and was never ours to license. If you reuse the numbers or the method, attribution is welcome
but not required by MIT; attribution for the *prior work* described above is a courtesy, not a licence
condition.

## Responsible use

The material describes a memory-safety bug in a specific PHP build. It is published for defenders:
to recognise the traffic pattern, to verify that a patch is in place, and to test their own
infrastructure. The arming requests are destructive by construction — they exhaust the target's memory
limit and crash a worker — so running them against anything you do not own is both illegal in most
jurisdictions and trivially visible in logs.
