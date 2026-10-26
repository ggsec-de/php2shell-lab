# fpm_state.gdb - the same measurement as gdb/chain_state.gdb, for PHP-FPM.
#
# The FPM build keeps its symbols in the php-fpm executable, not in a libphp.so, so the module range has
# to be looked up under a different name. Everything else is identical: the point is to read the engine's
# own state - PS(id), the main chunk, the symbol offsets - instead of inferring anything from responses.
#
#   sudo gdb -q -batch -p <fpm worker host pid> -x fpm_state.gdb
set pagination off
set confirm off
set width 0

python
import gdb

CHUNK = 0x200000
PS_ID = 0x10


def mem(addr, size):
    try:
        return gdb.selected_inferior().read_memory(addr, size).tobytes()
    except Exception:
        return None


def q(addr, size=8):
    raw = mem(addr, size)
    return None if raw is None else int.from_bytes(raw, "little")


def module_range(pid, needle="php-fpm"):
    lo = hi = 0
    try:
        with open("/proc/%d/maps" % pid) as fh:
            for line in fh:
                if needle not in line:
                    continue
                start, _, end = line.split()[0].partition("-")
                s, e = int(start, 16), int(end, 16)
                lo = s if not lo or s < lo else lo
                hi = max(hi, e)
    except OSError:
        pass
    return lo, hi


pid = gdb.selected_inferior().pid
exe, exe_end = module_range(pid)
print("[fs] php-fpm=%#x-%#x" % (exe, exe_end))
try:
    ps = int(gdb.parse_and_eval("(unsigned long)&ps_globals"))
    ag = int(gdb.parse_and_eval("(unsigned long)&alloc_globals"))
except Exception as exc:
    print("[fs] symbols unavailable: %r" % (exc,))
    print("[fs] the FPM image is stripped; use a build with symbols for calibration")
    raise SystemExit
heap = q(ag) or 0
main = heap & ~(CHUNK - 1)
psid = q(ps + PS_ID) or 0
print("[fs] heap=%#x main=%#x PS(id)=%#x" % (heap, main, psid))
if psid:
    print("[fs] id chunk=%#x offset=%#x" % (psid & ~(CHUNK - 1), psid & (CHUNK - 1)))
for name in ("zval_ptr_dtor", "zif_system", "zend_hash_destroy", "php_url_encode"):
    try:
        addr = int(gdb.parse_and_eval("(unsigned long)&%s" % name))
    except Exception:
        print("[fs] %s: not in this symbol table" % name)
        continue
    print("[fs] %s = php-fpm + %#x" % (name, addr - exe))
raw = mem(ps, 0x200)
if raw:
    interesting = []
    for off in range(0, 0x200, 8):
        v = int.from_bytes(raw[off:off + 8], "little")
        if main and main <= v < main + CHUNK:
            interesting.append((off, v))
    for off, v in interesting[:8]:
        print("[fs] ps_globals+%#x -> main+%#x" % (off, v - main))
end
