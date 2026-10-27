<?php
// Placement test. Prints only the build identity, nothing about the site.
// Upload next to wp-config.php, open it, delete it immediately.
header('Content-Type: text/plain; charset=utf-8');
echo 'PING-OK', "\n";
echo 'PHP_VERSION ', PHP_VERSION, "\n";
echo 'PHP_SAPI    ', PHP_SAPI, "\n";
echo 'PHP_OS      ', PHP_OS, ' / ', php_uname('m'), "\n";
echo 'DOCROOT     ', __DIR__, "\n";
