#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 GG ADVANCED IT Security UG

"""arming_gate.py - decide whether A1 actually armed the target before B1 is spent on it.

The chain hinges on one very specific failure: a refused 4096-byte allocation inside the session
encoder, with the request already past the point where the session id is adopted. Any other refusal
(the 1.5 MB value, a 2 MiB chunk, a 3 MB copy) means the build charges its limits differently and B1
cannot work. On 8.4.27 that difference is invisible from the client except as "B1 returned a short
body" - so it is checked here, once, on the A1 evidence.

Evidence comes from two places, strongest first:

  container log    `docker logs --since <timestamp>` sliced to this run: the fatal text names the
                   allocation size, which is exactly the signature. When a log is available it is the
                   only source used -- the body can show a 4096 refusal from a different allocation
                   while the log shows the real one, and treating the union as evidence would report
                   "armed" on a build that refused at the wrong place.
  A1 response      display_errors Off often hides the text from the body, so the body alone can only
                   prove "the request died"; that is a warn (exit 4), not a pass. Used only when no
                   container log could be read.

exit: 0 armed (4096), 2 not armed / wrong failure, 3 A1 could not reach the target,
      4 died but unverifiable without a container log

usage:
  arming_gate.py --a1-output /tmp/a1.txt --container p2s-target --since 2026-10-29T10:00:00Z
  arming_gate.py --a1-output /tmp/a1.txt --allow-unverified
"""
import argparse
import re
import shutil
import subprocess
import sys

ARM_SIGNATURE = 4096


def docker_logs(container, since):
    docker = shutil.which("docker")
    if not docker:
        return None, "docker not on PATH"
    cmd = [docker, "logs"]
    if since:
        cmd += ["--since", since]
    cmd.append(container)
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError) as exc:
        return None, str(exc)
    if proc.returncode != 0:
        lines = (proc.stderr or "docker logs failed").strip().splitlines()
        return None, lines[-1] if lines else "docker logs failed"
    return proc.stdout + proc.stderr, ""


def main(argv=None):
    ap = argparse.ArgumentParser(description="gate B1 on the A1 arming evidence")
    ap.add_argument("--a1-output", required=True, help="file holding the a1_arm.py output")
    ap.add_argument("--container", default="", help="target container name for the log check")
    ap.add_argument("--since", default="", help="RFC3339 timestamp taken just before A1")
    ap.add_argument("--allow-unverified", action="store_true",
                    help="treat 'died, no log available' as a pass instead of exit 4")
    args = ap.parse_args(argv)

    try:
        with open(args.a1_output, "r", encoding="utf-8", errors="replace") as handle:
            a1 = handle.read()
    except OSError as exc:
        print("cannot read A1 output: %s" % exc, file=sys.stderr)
        return 3

    if "no target on" in a1:
        print("A1 could not reach the target", file=sys.stderr)
        return 3

    body_sizes = sorted({int(m) for m in re.findall(r"tried to allocate (\d+)", a1)})

    log_text, log_error = None, "no --container given"
    if args.container:
        log_text, log_error = docker_logs(args.container, args.since)

    log_sizes = []
    if log_text:
        log_sizes = sorted({int(m) for m in re.findall(r"tried to allocate (\d+)", log_text)})

    # The log, when it says anything, wins outright. Unioning the two sources lets a body-side 4096
    # outvote a log-side 3014656 and report "armed" with the log cited as evidence for the opposite.
    notes = []
    if log_sizes:
        sizes, source = log_sizes, "container log"
        if not args.since:
            notes.append("no --since, so the log was not sliced to this run")
        if ARM_SIGNATURE in body_sizes and ARM_SIGNATURE not in log_sizes:
            notes.append("the body mentioned 4096 but the log did not - the log is authoritative")
    elif body_sizes:
        sizes, source = body_sizes, "response body"
        if log_text is None:
            notes.append("container log not consulted (%s)" % log_error)
        else:
            notes.append("the log carries no allocation size, so the body is all there is")
    else:
        sizes, source = [], "none"
        if log_text is None and args.container:
            notes.append("container log not consulted (%s)" % log_error)

    def explain():
        for note in notes:
            print("  note: %s" % note, file=sys.stderr)

    if ARM_SIGNATURE in sizes:
        print("armed: 4096-byte refusal at the encoder (%s)" % source)
        other = [s for s in sizes if s != ARM_SIGNATURE]
        if other:
            print("  note: other allocations also failed: %s" % ", ".join(map(str, other)))
        sys.stdout.flush()
        explain()
        return 0

    if sizes:
        print("not armed: failure was %s, not %d (%s)" % (
            ", ".join(map(str, sizes)), ARM_SIGNATURE, source), file=sys.stderr)
        explain()
        print("  this build charges its limit checks in different units - the arming shape does not "
              "land at php_url_encode (docs/VERSION_MATRIX.md)", file=sys.stderr)
        return 2

    died = bool(re.search(r'"sockerr":\s*"[^"]+', a1))
    if died:
        if log_text is None:
            print("unverified: A1 died, but no container log (%s)" % log_error, file=sys.stderr)
            if args.allow_unverified:
                print("  continuing on --allow-unverified")
                return 0
            print("  pass --container <name> or --allow-unverified to continue", file=sys.stderr)
            return 4
        print("not armed: A1 died but no allocation size appears in the log - most likely "
              "post_max_size, a proxy limit or a different ini", file=sys.stderr)
        explain()
        return 2

    print("not armed: A1 completed without an OOM", file=sys.stderr)
    explain()
    return 2


if __name__ == "__main__":
    sys.exit(main())
