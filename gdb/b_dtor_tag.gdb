# b_dtor_tag.gdb - how exactly do the HashTable destructors appear in the disclosed chunk?
#
# The cookie shows the repeated pointer as libphp+0x63812B while the plain symbol sits at
# libphp+0x638120, so the stored value carries a small tag in its low bits. This probe counts both
# forms separately inside the chunk the leak reads from, so the parser can match the same shape the
# encoder copies instead of assuming an untagged pointer.
#
#   sudo gdb -q -batch -p <worker> -x gdb/b_dtor_tag.gdb
set pagination off
set confirm off
set width 0

break php_url_encode if $x1 == 0xc8000
continue

python
import gdb

SYM = 0x638120
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
psid = q(int(gdb.parse_and_eval("(unsigned long)&ps_globals")) + PS_ID) or 0
base = psid & ~(CHUNK - 1) if psid else 0
print("[dt] libphp=%#x  PS(id)=%#x chunk=%#x" % (lib, psid, base))
if base:
    exact = 0
    tags = {}
    examples = []
    for page in range(1, 512):
        raw = mem(base + page * PAGE, PAGE)
        if raw is None:
            break
        for off in range(0, PAGE, 8):
            v = int.from_bytes(raw[off:off + 8], "little")
            if not v or not (lib <= v < libend):
                continue
            delta = v - lib
            if delta == SYM:
                exact += 1
            if SYM <= delta < SYM + 0x40:
                tag = delta - SYM
                tags[tag] = tags.get(tag, 0) + 1
                if len(examples) < 6:
                    examples.append((page * PAGE + off, v))
    print("[dt] exact libphp+%#x: %d" % (SYM, exact))
    print("[dt] tagged forms: " + ", ".join("+%#x x%d" % (t, c) for t, c in sorted(tags.items())))
    for addr, v in examples:
        print("[dt]   +%#x = %#x" % (addr, v))
end
