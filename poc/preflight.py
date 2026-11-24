#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 GG ADVANCED IT Security UG

"""preflight.py - recon and hard gate before A1.

The chain is pinned to one build family and one SAPI. Pointed at anything else it still sends ~1 MB
of body per step and then fails somewhere in the middle, which reads like a broken exploit instead of
an incompatible target. This script answers the cheap questions first and refuses the run when an
answer is known to be wrong.

Two levels:

  remote only (default)     Server header, X-Powered-By, the expose_php easter egg. No files needed.
  with --probe /probe.php   probe.php is fetched: sapi, ini values, and a pid sample for the pool size.

Verdicts:

  ok      nothing in the way
  warn    not a hard blocker, but the run may need tuning or may fail at a later step
  fail    a measured property the chain cannot cross (exit 2)
  arming  the arming step is reproducible but the disclosure step is not, so a chain run cannot
          succeed on this build. The useful run is preflight -> A1 -> gate, then stop (exit 5)

usage:
  preflight.py --url http://127.0.0.1:18110/index.php
  preflight.py --url http://127.0.0.1:18110/index.php --probe /probe.php
  preflight.py --url ... --allow-version --allow-sapi --allow-memory-limit   # override, warns instead
"""
import argparse
import http.client
import json
import re
import sys
import urllib.parse

from decode_leak_cookie import SYMBOL_PROFILES, profile_key

ARMED_FULL = {"8.4.26", "8.4.24"}  # end-to-end chain verified (8.4.24 = Debian 13 package)
ARMED_ARMING = {"8.5.11"}        # 4096 signature reproduced; disclosure does not transfer
PREFORK_SAPIS = {"apache2handler"}
BAD_SAPIS = {"fpm-fcgi", "cgi-fcgi", "php-fpm", "cli", "embed"}
WARN_SAPIS = {"cli-server"}      # one long-lived process, no fork: untested, worth a try
EASTER_EGG = "/?=PHPE9568F34-D428-11d2-A769-00AA001ACF42"
PROBE_SAMPLES = 6

BOUNDARY = "C" * 10


class Report:
    def __init__(self):
        self.failures = 0
        self.warnings = 0
        self.arming_only = 0

    def line(self, level, key, text):
        print("[%-4s] %-14s %s" % ({"arming": "ARM"}.get(level, level), key, text))
        if level == "fail":
            self.failures += 1
        elif level == "warn":
            self.warnings += 1
        elif level == "arming":
            self.arming_only += 1


def split_url(url):
    rest = url.split("://", 1)[-1]
    hostport, _, path = rest.partition("/")
    host, _, port = hostport.partition(":")
    scheme = "https" if url.startswith("https://") else "http"
    return scheme, host, int(port or (443 if scheme == "https" else 80)), "/" + path


def request(url, path, body=None, headers=None):
    scheme, host, port, _ = split_url(url)
    conn_cls = http.client.HTTPSConnection if scheme == "https" else http.client.HTTPConnection
    conn = conn_cls(host, port, timeout=15)
    try:
        conn.request("GET" if body is None else "POST", path, body=body, headers=headers or {})
        resp = conn.getresponse()
        return resp.status, resp.getheaders(), resp.read()
    finally:
        conn.close()


def probe_body(pid_probe=True):
    fields = [("PHPSESSID", "preflight"), ("PHP_SESSION_UPLOAD_PROGRESS", "preflight")]
    if pid_probe:
        fields.append(("probe", "1"))
    out = bytearray()
    for name, value in fields:
        out.extend(("--%s\r\nContent-Disposition: form-data; name=\"%s\"\r\n\r\n%s\r\n"
                    % (BOUNDARY, name, value)).encode())
    out.extend(("--%s--\r\n" % BOUNDARY).encode())
    return bytes(out)


def to_bytes(text):
    """post_max_size / memory_limit shorthand -> bytes, None when it is not a size."""
    match = re.fullmatch(r"\s*(\d+)\s*([KMG])?\s*", text or "", re.I)
    if not match:
        return None
    value = int(match.group(1))
    return value * {"K": 1024, "M": 1024 ** 2, "G": 1024 ** 3, None: 1}[
        (match.group(2) or "").upper() or None]


def check_version(version, report, args):
    if version in ARMED_FULL:
        report.line("ok", "php", "%s - full chain verified on this build" % version)
    elif version in ARMED_ARMING:
        # The arming half of the chain is reproducible here, the disclosure half is not: 8.5.11 hands
        # PS(id) to the encoder as a refcounted copy of someone else's string instead of a fresh object,
        # so php_session_send_cookie is never called and B1 has nothing to leak. Carrying on would spend
        # the body and fail in the middle, which is the exact failure mode preflight exists to prevent.
        if args.allow_arming_only:
            report.line("warn", "php", "%s - arming only, B1 will not disclose (-allow-arming-only)"
                        % version)
        else:
            report.line("arming", "php", "%s - arming reproduces, disclosure does not: "
                                        "B1 cannot succeed on this build (docs/VERSION_MATRIX.md"
                                        "#porting-to-8511). Use --allow-arming-only to verify the "
                                        "arming instrument and stop there" % version)
    elif version:
        level = "warn" if args.allow_version else "fail"
        report.line(level, "php", "%s - not an armed build (8.4.26 only; 8.4.27, 8.5.12, 8.3.36, "
                                "8.2.35 measured clean)" % version)


def main(argv=None):
    ap = argparse.ArgumentParser(description="recon and gate before arming")
    ap.add_argument("--url", required=True)
    ap.add_argument("--probe", default="", help="path of a deployed probe.php, e.g. /probe.php")
    ap.add_argument("--allow-version", action="store_true",
                    help="downgrade a non-armed PHP version from fail to warn")
    ap.add_argument("--allow-sapi", action="store_true", help="downgrade a non-prefork SAPI")
    ap.add_argument("--allow-memory-limit", action="store_true",
                    help="downgrade a memory_limit other than 128M")
    ap.add_argument("--allow-ini", action="store_true",
                    help="downgrade a post_max_size below 2M or cleanup off")
    ap.add_argument("--allow-arming-only", action="store_true",
                    help="downgrade an arming-only build (8.5.11) from exit 5 to a warning")
    ap.add_argument("--json", action="store_true", help="print the collected facts as JSON as well")
    args = ap.parse_args(argv)

    report = Report()
    facts = {}
    scheme, host, port, path = split_url(args.url)

    # 1. reachability ------------------------------------------------------
    try:
        status, headers, body = request(args.url, path)
    except OSError as exc:
        print("no target on %s:%d (%s)" % (host, port, exc), file=sys.stderr)
        return 3
    facts["http_status"] = status
    report.line("ok" if status < 500 else "warn", "reachable", "HTTP %d on %s" % (status, path))

    # 2. front end and SAPI hints -----------------------------------------
    lower = {name.lower(): value for name, value in headers}
    server = lower.get("server", "")
    powered = lower.get("x-powered-by", "")
    facts["server"] = server
    facts["x_powered_by"] = powered
    if server:
        report.line("info", "server", server)
    if re.search(r"apache", server, re.I):
        report.line("ok", "front", "Apache")
    elif re.search(r"nginx", server, re.I):
        # nginx in front does not decide the SAPI, but it does add the 1 MiB default body limit and
        # it usually means FPM. --probe settles it.
        report.line("warn", "front", "nginx - check client_max_body_size (arming body is ~1 MiB) "
                                    "and expect FPM unless --probe says otherwise")
    elif server:
        report.line("warn", "front", "unrecognised front end %r" % server)
    else:
        report.line("warn", "front", "no Server header; front end unknown")

    # 3. PHP version -------------------------------------------------------
    version = None
    match = re.search(r"PHP/(\d+\.\d+\.\d+)", powered)
    if match:
        version = match.group(1)
    else:
        try:
            _, _, egg = request(args.url, EASTER_EGG)
            match = re.search(rb"PHP Version\s+(\d+\.\d+\.\d+)", egg)
            if match:
                version = match.group(1).decode()
        except OSError:
            pass
    facts["php_version"] = version
    if version:
        check_version(version, report, args)
    else:
        report.line("info", "php", "version not detectable from headers/easter egg; trying the probe")

    # 4. probe: SAPI, ini, pool size --------------------------------------
    if args.probe:
        probe_path = args.probe if args.probe.startswith("/") else "/" + args.probe
        try:
            status, _, body = request(
                args.url, probe_path, probe_body(pid_probe=False),
                {"Content-Type": "multipart/form-data; boundary=" + BOUNDARY})
        except OSError as exc:
            report.line("warn", "probe", "%s unreachable (%s); ini and SAPI not measured"
                        % (probe_path, exc))
            status, body = 0, b""
        if status == 200:
            try:
                data = json.loads(body.decode("utf-8", "replace"))
            except ValueError:
                report.line("warn", "probe", "%s answered non-JSON; ini and SAPI not measured"
                            % probe_path)
                data = {}
            if not facts.get("php_version") and data.get("php"):
                facts["php_version"] = data["php"]
                check_version(data["php"], report, args)

            # Architecture: the key by which symbol offsets are selected. A target reporting anything
            # else than these two has no profile and needs --symbol from its own nm.
            arch = (data.get("arch") or "").strip()
            facts["arch"] = arch
            normalised = {"x86_64": "x86_64", "amd64": "x86_64",
                          "aarch64": "arm64", "arm64": "arm64"}.get(arch)
            if normalised:
                distro = (data.get("distro") or "").strip()
                facts["distro"] = distro
                report.line("ok", "arch", "%s (%s%s)" % (arch, data.get("os") or "?",
                                                         ", " + distro if distro else ""))
                profile = profile_key(normalised, facts.get("php_version"), distro)
                if facts.get("php_version") and profile not in SYMBOL_PROFILES:
                    report.line("warn", "symbols", "no offset profile for %s - the chain will need "
                                                  "--symbol zval_ptr_dtor=0x...,zif_system=0x...,"
                                                  "zend_hash_destroy=0x... from that binary"
                                % profile)
            elif arch:
                report.line("warn", "arch", "unrecognised %r" % arch)
            sapi = data.get("sapi")
            facts["sapi"] = sapi
            facts["ini"] = {key: data.get(key) for key in
                            ("memory_limit", "post_max_size", "display_errors",
                             "session.upload_progress.cleanup")}
            if sapi in PREFORK_SAPIS:
                report.line("ok", "sapi", sapi)
            elif sapi in BAD_SAPIS:
                level = "warn" if args.allow_sapi else "fail"
                report.line(level, "sapi", "%s - the chain needs a prefork mod_php worker that "
                                           "survives a bailout (docs/FPM.md)" % sapi)
            elif sapi in WARN_SAPIS:
                report.line("warn", "sapi", "%s - a single long-lived process; untested, but no "
                                           "worker replacement either" % sapi)

            limit = to_bytes(data.get("memory_limit"))
            facts["memory_limit_bytes"] = limit
            if limit == 128 * 1024 ** 2:
                report.line("ok", "memory_limit", "128M")
            elif limit is not None:
                level = "warn" if args.allow_memory_limit else "fail"
                report.line(level, "memory_limit", "%s - the arming shapes are tuned for 128M"
                            % data.get("memory_limit"))

            # post_max_size: the arming body is ~1.04 MiB and is de-chunked before parsing, so an
            # 8 MB default is fine and 2 MB is the floor.
            post_max = to_bytes(data.get("post_max_size"))
            facts["post_max_size_bytes"] = post_max
            if post_max is None:
                report.line("warn", "post_max_size", "unparsed value %r"
                            % data.get("post_max_size"))
            elif post_max < 2 * 1024 ** 2:
                level = "warn" if args.allow_ini else "fail"
                report.line(level, "post_max_size", "%s - below the ~1.04 MiB arming body plus "
                                                     "de-chunk buffer" % data.get("post_max_size"))
            elif post_max < 4 * 1024 ** 2:
                report.line("warn", "post_max_size", "%s - close to the arming body"
                            % data.get("post_max_size"))
            else:
                report.line("ok", "post_max_size", data.get("post_max_size") or "unset")

            # cleanup=On is what removes the progress key again; the chain relies on it.
            cleanup = str(data.get("session.upload_progress.cleanup") or "").strip().lower()
            facts["upload_progress_cleanup"] = cleanup
            if cleanup in ("1", "on", "yes", "true"):
                report.line("ok", "cleanup", "session.upload_progress.cleanup=%s"
                            % data.get("session.upload_progress.cleanup"))
            else:
                level = "warn" if args.allow_ini else "fail"
                report.line(level, "cleanup", "session.upload_progress.cleanup=%r - the chain needs "
                                              "On" % data.get("session.upload_progress.cleanup"))

            if str(data.get("display_errors") or "").strip().lower() in ("1", "on", "yes", "true"):
                report.line("info", "display_errors", "On - the fatal text also shows up in the "
                                                      "A1 body, which only makes the gate easier")
        elif status:
            report.line("warn", "probe", "%s answered HTTP %d; ini and SAPI not measured"
                        % (probe_path, status))

        # pool size: distinct pids over a handful of requests
        pids = set()
        for _ in range(PROBE_SAMPLES):
            try:
                status, _, body = request(
                    args.url, probe_path, probe_body(),
                    {"Content-Type": "multipart/form-data; boundary=" + BOUNDARY})
            except OSError:
                break
            if status != 200:
                break
            try:
                pid = json.loads(body.decode("utf-8", "replace")).get("pid")
            except ValueError:
                break
            if pid:
                pids.add(pid)
        facts["sampled_pids"] = len(pids)
        if len(pids) > 1:
            report.line("warn", "workers", "at least %d distinct pids in %d requests - pass "
                                           "--workers <MaxRequestWorkers> so one child is pinned"
                        % (len(pids), PROBE_SAMPLES))
        elif pids:
            report.line("ok", "workers", "one pid in %d requests" % PROBE_SAMPLES)
    else:
        report.line("info", "probe", "no --probe: ini, SAPI and pool size not measured")

    if not facts.get("php_version"):
        level = "warn" if args.allow_version else "fail"
        report.line(level, "php", "version still unknown - pass --probe /probe.php or "
                                  "--allow-version")

    if args.json:
        print(json.dumps(facts, indent=2, default=str))

    if report.failures:
        verdict, code = "FAIL", 2
    elif report.arming_only:
        verdict, code = "ARMING-ONLY", 5
    elif report.warnings:
        verdict, code = "PASS with warnings", 0
    else:
        verdict, code = "PASS", 0
    print("verdict: %s (%d fail, %d arming-only, %d warn)"
          % (verdict, report.failures, report.arming_only, report.warnings))
    return code


if __name__ == "__main__":
    sys.exit(main())
