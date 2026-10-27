<?php
/*
 * Read-only build check for ggsec.de.
 *
 * Answers two questions and changes nothing:
 *   1. which PHP build is serving the site (so the var_destroy UAF range can be checked
 *      without running anything that crashes);
 *   2. whether the site's own code contains unserialize() call sites, which is the
 *      precondition the bug needs. Finding a call site is not a finding on its own --
 *      what matters is whether request data can reach it.
 *
 * Upload under a random name, set $TOKEN below, open with ?k=<token>, delete it after.
 * No writes, no shell, no network, no output of passwords or keys.
 */

declare(strict_types=1);

$TOKEN = 'eowidm4932849327912124';

if (!isset($_GET['k']) || !hash_equals($TOKEN, (string) $_GET['k'])) {
    http_response_code(404);
    exit;
}

header('Content-Type: text/plain; charset=utf-8');

function row(string $label, $value): void
{
    if (is_bool($value)) {
        $value = $value ? 'true' : 'false';
    } elseif (is_array($value)) {
        $value = $value === [] ? '(none)' : implode(', ', $value);
    }
    printf("%-34s %s\n", $label, (string) $value);
}

function section(string $title): void
{
    echo "\n== ", $title, " ", str_repeat('=', max(0, 58 - strlen($title))), "\n";
}

section('PHP build');
row('PHP_VERSION', PHP_VERSION);
row('PHP_VERSION_ID', PHP_VERSION_ID);
row('PHP_SAPI', PHP_SAPI);
row('PHP_OS / machine', PHP_OS . ' / ' . php_uname('m'));
row('Zend Engine', zend_version());
row('thread safety', defined('ZEND_THREAD_SAFE') && ZEND_THREAD_SAFE ? 'ZTS' : 'NTS');
row('int size', PHP_INT_SIZE * 8 . '-bit');
row('unserialize() available', function_exists('unserialize'));
row('loaded ini file', php_ini_loaded_file() ?: '(none)');
row('scanned ini files', php_ini_scanned_files() ?: '(none)');

section('Limits and session settings');
foreach ([
    'memory_limit',
    'post_max_size',
    'upload_max_filesize',
    'max_file_uploads',
    'max_input_vars',
    'max_input_time',
    'max_execution_time',
    'session.save_handler',
    'session.serialize_handler',
    'session.use_strict_mode',
    'session.use_cookies',
    'session.upload_progress.enabled',
    'session.upload_progress.cleanup',
    'session.upload_progress.prefix',
    'session.upload_progress.name',
] as $key) {
    row($key, ini_get($key));
}
row('opcache.enable', function_exists('opcache_get_status') ? ini_get('opcache.enable') : 'extension absent');
row('opcache.preload', ini_get('opcache.preload') ?: '(none)');

$disabled = array_filter(array_map('trim', explode(',', (string) ini_get('disable_functions'))));
row('disable_functions', $disabled);

section('WordPress');
if (function_exists('get_bloginfo')) {
    row('core version', get_bloginfo('version'));
    $plugins = (array) get_option('active_plugins', []);
    row('active plugins', count($plugins));
    foreach ($plugins as $plugin) {
        echo '  - ', $plugin, "\n";
    }
    $theme = wp_get_theme();
    row('theme', $theme->get('Name') . ' ' . $theme->get('Version'));
    row('REST users endpoint', get_option('permalink_structure') !== '' ? 'permalinks on' : 'plain');
} else {
    row('WordPress loaded', false);
}

section('unserialize() call sites under wp-content');
$root = defined('WP_CONTENT_DIR') ? WP_CONTENT_DIR : dirname(__DIR__) . '/wp-content';
$patterns = [
    'unserialize(' => '/\bunserialize\s*\(/i',
    'maybe_unserialize(' => '/\bmaybe_unserialize\s*\(/i',
    'unserialize(base64_decode' => '/unserialize\s*\(\s*(?:base64_decode|stripslashes|urldecode|gzinflate|gzuncompress)/i',
];
$counts = array_fill_keys(array_keys($patterns), 0);
$hits = [];
$files = 0;
$maxHits = 120;

$limit = (int) ini_get('max_execution_time');
$budget = $limit > 0 ? max(5, $limit - 5) : 25;
$budget = min($budget, 25);
$started = microtime(true);
$complete = true;

if (is_dir($root)) {
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS)
    );
    foreach ($iterator as $file) {
        if (microtime(true) - $started > $budget) {
            $complete = false;
            break;
        }
        if (!$file->isFile() || strtolower($file->getExtension()) !== 'php') {
            continue;
        }
        $files++;
        $source = @file_get_contents($file->getPathname(), false, null, 0, 512 * 1024);
        if ($source === false) {
            continue;
        }
        foreach ($patterns as $name => $regex) {
            if (!preg_match_all($regex, $source, $m)) {
                continue;
            }
            $counts[$name] += count($m[0]);
            foreach ($m[0] as $occurrence) {
                if (count($hits) >= $maxHits) {
                    continue;
                }
                $hits[] = str_replace($root, 'wp-content', $file->getPathname()) . '  [' . $name . ']';
            }
        }
    }
    row('php files scanned', $files);
    row('scan completed', $complete ? 'yes' : 'NO - budget ' . $budget . 's reached');
    foreach ($counts as $name => $count) {
        row($name, $count);
    }
    echo "\n";
    if ($hits === []) {
        echo "  no call sites found\n";
    } else {
        echo implode("\n", array_unique($hits)), "\n";
        echo count($hits) >= $maxHits ? "\n  (list truncated at {$maxHits})\n" : '';
    }
} else {
    row('wp-content', 'not found at ' . $root);
}

echo "\nDone. Delete this file now.\n";
