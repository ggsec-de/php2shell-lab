# b1_path_hits.gdb - how far does the session path get during the disclosure request?
#
# The disclosure needs php_session_send_cookie, which is guarded by
# `if (PS(use_cookies) && PS(send_cookie))`. That guard is identical in 8.4.26 and 8.5.11, so if the
# encoder is never called on 8.5.11 either the flag is clear or the path never arrives. Counting hits on
# the two functions that bracket it answers which, without stopping the worker.
#
#   sudo gdb -q -batch -p <worker> -x gdb/b1_path_hits.gdb &
#   python3 poc/b1_forge.py --url ... --spec ...
set pagination off
set confirm off
set width 0

python
import gdb


class Count(gdb.Breakpoint):
    def __init__(self, spec):
        super().__init__(spec, internal=False)
        self.hits = 0

    def stop(self):
        self.hits += 1
        print("[p] %-26s hit %d" % (self.location, self.hits))
        return False


reset_id = Count("php_session_reset_id")
send_cookie = Count("php_session_send_cookie")
initialize = Count("php_session_initialize")
end

continue
