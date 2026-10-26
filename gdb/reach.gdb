# reach.gdb - is the session encoder even reached on a given build?
#
# The 8.4.27 arming requests always die on a whole-chunk (2 MiB) allocation, never on the one-page
# allocation at the encoder. That leaves one question the response cannot answer: does the request ever
# get as far as the encoder, or does the fix stop it earlier? Breakpoints answer it, and they only need
# the exported symbols, so a stripped build is enough.
#
#   sudo gdb -q -batch -p <worker pid> -x reach.gdb > /tmp/reach.log 2>&1 &
#   ... send requests ...
#   grep '^\[reach\]' /tmp/reach.log
set pagination off
set confirm off
set width 0

python
import gdb

TARGETS = [
    "php_url_encode",             # the disclosure encoder: the allocation the chain needs to fail
    "php_session_initialize",
    "php_session_reset_id",
    "php_session_start",
]

class Hit(gdb.Breakpoint):
    def __init__(self, name):
        super().__init__(name, internal=True)
        self.name = name

    def stop(self):
        try:
            pid = gdb.selected_inferior().pid
            print("[reach] %s hit (pid %d)" % (self.name, pid), flush=True)
        except Exception as exc:
            print("[reach] %s hit (print failed: %r)" % (self.name, exc), flush=True)
        return False


for name in TARGETS:
    try:
        Hit(name)
        print("[reach] armed %s" % name, flush=True)
    except Exception as exc:
        print("[reach] cannot arm %s: %s" % (name, str(exc).splitlines()[0] if str(exc) else ""), flush=True)

print("[reach] watching; send the request now", flush=True)
end
continue
