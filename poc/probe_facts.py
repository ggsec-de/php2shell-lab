#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 GG ADVANCED IT Security UG

"""probe_facts.py - read the target architecture and PHP version off a deployed probe.php.

Both facts select the offset profile: the offsets differ by tens of MB between architectures and by
the whole build between PHP versions, so neither may be guessed when a probe can answer. The third
field is the distribution, which separates a package build from the official image at the same
version. A missing or non-JSON probe is not an error - the caller falls back to the leak for the
architecture and to the default version.

usage:
  probe_facts.py http://127.0.0.1:18110/index.php /probe.php   # "x86_64<TAB>8.4.26<TAB>debian13"
"""
import json
import sys
import urllib.request

ALIASES = {"amd64": "x86_64", "aarch64": "arm64"}


def main(argv):
    if len(argv) < 3:
        return 2
    target, probe = argv[1], argv[2]
    url = "%s/%s" % (target.rsplit("/", 1)[0], probe.lstrip("/"))
    try:
        with urllib.request.urlopen(url, timeout=10) as response:
            data = json.loads(response.read().decode("utf-8", "replace"))
    except (OSError, ValueError):
        return 1
    arch = (data.get("arch") or "").strip()
    if not arch:
        return 1
    print("%s\t%s\t%s" % (ALIASES.get(arch, arch), (data.get("php") or "").strip(),
                          (data.get("distro") or "").strip()))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
