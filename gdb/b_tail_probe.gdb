# b_tail_probe.gdb - did the tail-vars HashTables land inside the stale session-id chunk?
#
# The leak window reads forward from PS(id) up to page 0x1f7 of the chunk. Module pointers can only
# appear there if real HashTables (pDestructor = zval_ptr_dtor) are allocated in the pages the forged
# value left free. This probe answers that directly: it locates the chunk from ps_globals, walks all
# 512 pages, and histograms every qword that points into libphp, singling out zval_ptr_dtor.
#
#   sudo gdb -q -batch -p <worker> -x gdb/b_tail_probe.gdb
set pagination off
set confirm off
set width 0

python
import gdb

ZVAL_PTR_DTOR = 0x638120
PS_ID = 0x10
CHUNK = 0x200000
PAGE = 0x1000


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


pid = gdb.selected_inferior().pid
lib, libend = module_range(pid)
try:
    ps = int(gdb.parse_and_eval("(unsigned long)&ps_globals"))
    psid = q(ps + PS_ID) or 0
except Exception:
    psid = 0
base = psid & ~(CHUNK - 1) if psid else 0
print("[tp] libphp=%#x-%#x PS(id)=%#x chunk=%#x" % (lib, libend, psid, base))
if not base:
    print("[tp] no session id -> nothing to scan")
else:
    print("[tp] chunk free_pages=%d free_tail=%d"
          % (q(base + 0x18, 4) or 0, q(base + 0x1c, 4) or 0))
    per_page = {}
    zdtor = []
    total = 0
    for page in range(1, 512):
        raw = mem(base + page * PAGE, PAGE)
        if raw is None:
            break
        hits = 0
        for off in range(0, PAGE, 8):
            v = int.from_bytes(raw[off:off + 8], "little")
            if lib and lib <= v < libend:
                hits += 1
                if v - lib == ZVAL_PTR_DTOR:
                    zdtor.append((page, off, v))
        if hits:
            per_page[page] = hits
            total += hits
    print("[tp] module pointers in chunk: %d on %d pages" % (total, len(per_page)))
    for page in sorted(per_page):
        print("[tp]   page %#x: %d" % (page, per_page[page]))
    print("[tp] zval_ptr_dtor hits: %d" % len(zdtor))
    for page, off, v in zdtor[:8]:
        print("[tp]   +%#x = %#x" % (page * PAGE + off, v))
end
