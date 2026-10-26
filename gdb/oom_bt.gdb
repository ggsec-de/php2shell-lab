# oom_bt.gdb - who asks for the allocation that fails?
#
# On the patched build every arming attempt dies on a 2 MiB allocation rather than the one-page one the
# chain needs, and the request never reaches the session encoder. A stripped image still exports several
# of the error and bailout entry points, so breaking on them and printing a short backtrace names the
# code path that gave up - which is the one fact the response cannot show.
#
# zend_error is not the one the allocator uses (it produced zero hits), so several candidates are armed
# and whichever exists in the image is reported.
#
#   sudo gdb -q -batch -p <worker> -x oom_bt.gdb > /tmp/oom.log 2>&1 &
#   ... send the request ...
#   grep -A12 'hit zend' /tmp/oom.log
set pagination off
set confirm off
set width 0

python
import gdb

CANDIDATES = [
    "zend_error_noreturn",
    "zend_error",
    "zend_bailout",
    "zend_mm_safe_error",
    "zend_out_of_memory",
    "php_error_docref",
]


class Hit(gdb.Breakpoint):
    def __init__(self, name):
        super().__init__(name, internal=True)
        self.name = name

    def stop(self):
        try:
            print("[oom] hit %s" % self.name, flush=True)
            gdb.execute("bt 10")
        except Exception as exc:
            print("[oom] %s (bt failed: %r)" % (self.name, exc), flush=True)
        return False


armed = []
for name in CANDIDATES:
    try:
        Hit(name)
        armed.append(name)
    except Exception:
        pass
print("[oom] armed: %s" % (", ".join(armed) or "none"), flush=True)
end
continue
