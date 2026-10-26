# a1_id_state.gdb - is the string under PS(id) still intact after the arming request?
#
# The arming step leaves PS(id) pointing into freed memory. Whether the next request survives depends
# on what is there: on 8.4.26 a readable string remains, so php_session_initialize can walk it and the
# encode that follows reads our forged length. On 8.5.11 the same walk faults inside ps_close_files,
# which suggests the string is gone.
#
# This probe answers it directly, with no breakpoints - attach to the worker right after A1:
#
#   sudo gdb -q -batch -p <worker> -x gdb/a1_id_state.gdb
#
# PS(id) is a zend_string*, so the interesting fields are its length (at +0x10) and its bytes (at +0x18).
set pagination off
set confirm off
set width 0

python
import gdb

PS_ID = 0x10


def read(inf, addr, size):
    try:
        return inf.read_memory(addr, size).tobytes()
    except Exception:
        return None


inf = gdb.selected_inferior()
ps = int(gdb.parse_and_eval("(unsigned long)&ps_globals"))
names = {0x10: "id", 0x18: "send_cookie", 0x20: "module_name", 0x28: "module"}
print("[a1] ps_globals=%#x" % ps)
for off, name in names.items():
    raw = read(inf, ps + off, 8)
    print("[a1]   +%#04x %-12s %s" % (off, name, "%#x" % int.from_bytes(raw, "little") if raw else "unreadable"))

psid = None
raw = read(inf, ps + PS_ID, 8)
if raw:
    psid = int.from_bytes(raw, "little")
if not psid:
    print("[a1] PS(id) is NULL - nothing armed")
else:
    print("[a1] PS(id)=%#x  page=%#x" % (psid, (psid & 0x1FFFFF) >> 12))
    gc = read(inf, psid, 8)
    h = read(inf, psid + 8, 8)
    ln = read(inf, psid + 0x10, 8)
    val = read(inf, psid + 0x18, 40)
    if gc is None:
        print("[a1] the struct itself is unreadable (freed and unmapped)")
    else:
        gc_i = int.from_bytes(gc, "little")
        h_i = int.from_bytes(h, "little") if h else 0
        ln_i = int.from_bytes(ln, "little") if ln else 0
        print("[a1] zend_string: gc=%#x (refcount=%d type=%#x) h=%#x len=%#x"
              % (gc_i, gc_i & 0xFFFFFFFF, (gc_i >> 32) & 0xFFFFFFFF, h_i, ln_i))
        if val is None:
            print("[a1] val[] is unreadable")
        else:
            printable = sum(1 for b in val if 32 <= b < 127)
            print("[a1] val[]=%r  (%d/%d printable)" % (val, printable, len(val)))
            plausible = ln_i <= 128 and printable > len(val) * 0.75
            print("[a1] verdict: %s" % ("INTACT - a readable string survives"
                                        if plausible else "CORRUPTED - length or bytes do not look like an id"))
end
detach
quit
