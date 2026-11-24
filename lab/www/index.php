<?php
// Target page for the php2shell lab.
//
// The first line ("OK") is the liveness marker the tooling greps for; the rest
// exposes the PHP parameters the chain depends on, so a curl of the target
// shows the configuration the demo is running against.
header("Content-Type: text/plain");
echo "OK\n";
echo "sapi=" . php_sapi_name() . " php=" . PHP_VERSION . " os=" . PHP_OS . "\n";
foreach ([
    "memory_limit",
    "post_max_size",
    "max_execution_time",
    "max_input_vars",
    "display_errors",
    "session.save_path",
    "session.upload_progress.enabled",
    "session.upload_progress.cleanup",
    "session.upload_progress.freq",
] as $k) {
    echo $k . "=" . ini_get($k) . "\n";
}
