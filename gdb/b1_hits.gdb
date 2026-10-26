# b1_hits.gdb - count encoder hits during one disclosure request without stopping the worker.
#
# Every earlier attempt to look inside the request stopped the worker for a memory scan, and on this
# allocator that is enough to change the outcome: the same stack appears on 8.4.26 with a debugger
# attached, while 8.4.26 discloses normally without one. This probe never stops: the breakpoint prints
# the two arguments and returns immediately, so the worker is held for microseconds, not milliseconds.
#
# What the arguments mean:
#   $x0  the buffer the encoder is about to read
#   $x1  its length - 0x20 for a normal session id, 0xc8000 when the forged header is in place
#
# usage:
#   sudo gdb -q -batch -p <worker> -x gdb/b1_hits.gdb &      # after the arming request
#   python3 poc/b1_forge.py --url ... --spec ...            # the request to watch
set pagination off
set confirm off
set width 0

python
import gdb

CHUNK = 0x200000
PS_ID = 0x10


class Hits(gdb.Breakpoint):
    count = 0

    def stop(self):
        Hits.count += 1
        try:
            x0 = int(gdb.parse_and_eval("$x0"))
            x1 = int(gdb.parse_and_eval("$x1"))
        except Exception:
            return False
        inf = gdb.selected_inferior()
        try:
            ps = int(gdb.parse_and_eval("(unsigned long)&ps_globals"))
            psid = int.from_bytes(inf.read_memory(ps + PS_ID, 8).tobytes(), "little")
        except Exception:
            psid = 0
        print("[h] hit %-2d buf=%#x len=%#x  page=%#x  PS(id)=%#x  match=%s"
              % (Hits.count, x0, x1, (x0 & (CHUNK - 1)) >> 12, psid, x0 == psid))
        return False          # keep running: the point is to observe, not to stop


Hits("php_url_encode", internal=False)
end

continue
