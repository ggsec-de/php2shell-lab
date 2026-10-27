<?php
/*
 * Read-only build check for ggsec.de.
 *
 * Answers three questions and changes nothing:
 *   1. which PHP build is serving the site;
 *   2. which plugins and themes are installed, with versions;
 *   3. where the site's own code calls unserialize(), and which of those files also
 *      touch request superglobals -- that pairing is the only precondition the
 *      var_destroy UAF needs that a hosting plan cannot supply by itself.
 *
 * Finding a call site is not a finding. What matters is whether request data reaches it.
 *
 * Upload under a random name, set $TOKEN, open with ?k=<token>, delete it after.
 * No writes, no shell, no network, no output of passwords or keys.
 */

declare(strict_types=1);

$TOKEN = 'CHANGE-ME-before-upload';

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

function header_value(string $file, string $field): ?string
{
    $source = @file_get_contents($file, false, null, 0, 8192);
    if ($source === false) {
        return null;
    }
    if (preg_match('/^[ \t\/*#@]*' . preg_quote($field, '/') . ':\s*(.+)$/mi', $source, $m)) {
        return trim($m[1]);
    }
    return null;
}

/* ---------------------------------------------------------------- build --- */

section('PHP build');
row('PHP_VERSION', PHP_VERSION);
row('PHP_VERSION_ID', PHP_VERSION_ID);
row('PHP_SAPI', PHP_SAPI);
row('PHP_OS / machine', PHP_OS . ' / ' . php_uname('m'));
row('Zend Engine', zend_version());
row('thread safety', defined('ZEND_THREAD_SAFE') && ZEND_THREAD_SAFE ? 'ZTS' : 'NTS');
row('int size', PHP_INT_SIZE * 8 . '-bit');
row('unserialize() available', function_exists('unserialize'));
row('this file', __FILE__);
row('loaded ini file', php_ini_loaded_file() ?: '(none)');

section('Limits and session settings');
foreach ([
    'memory_limit',
    'post_max_size',
    'upload_max_filesize',
    'max_file_uploads',
    'max_input_vars',
    'max_execution_time',
    'session.save_handler',
    'session.serialize_handler',
    'session.use_strict_mode',
    'session.upload_progress.enabled',
    'session.upload_progress.cleanup',
] as $key) {
    row($key, ini_get($key));
}
row('opcache.enable', function_exists('opcache_get_status') ? ini_get('opcache.enable') : 'extension absent');
row('disable_functions', array_filter(array_map('trim', explode(',', (string) ini_get('disable_functions')))));

/* ----------------------------------------------------------- site root --- */

section('Site root');

$siteRoot = null;
$probe = __DIR__;
for ($depth = 0; $depth < 5; $depth++) {
    if (is_file($probe . '/wp-config.php')) {
        $siteRoot = $probe;
        break;
    }
    $parent = dirname($probe);
    if ($parent === $probe) {
        break;
    }
    $probe = $parent;
}
row('wp-config.php found', $siteRoot ?? 'no (searched 5 levels up from this file)');

$contentCandidates = [];
if ($siteRoot !== null) {
    $contentCandidates[] = $siteRoot . '/wp-content';
}
$contentCandidates[] = __DIR__ . '/wp-content';
$contentCandidates[] = dirname(__DIR__) . '/wp-content';

$contentRoot = null;
foreach ($contentCandidates as $candidate) {
    if (is_dir($candidate)) {
        $contentRoot = $candidate;
        break;
    }
}
row('wp-content', $contentRoot ?? 'not found');
if ($contentRoot === null) {
    row('tried', $contentCandidates);
}

/* -------------------------------------------------------- plugin/theme --- */

if ($contentRoot !== null) {
    section('Installed plugins');
    $pluginDir = $contentRoot . '/plugins';
    $found = 0;
    foreach ((array) @scandir($pluginDir) as $entry) {
        if (!is_string($entry) || $entry === '.' || $entry === '..') {
            continue;
        }
        $path = $pluginDir . '/' . $entry;
        if (is_file($path) && substr($entry, -4) === '.php') {
            $name = header_value($path, 'Plugin Name');
            if ($name !== null) {
                $found++;
                printf("  %-34s %-10s %s\n", basename($entry, '.php'), header_value($path, 'Version') ?? '?', $name);
            }
            continue;
        }
        if (!is_dir($path)) {
            continue;
        }
        foreach ((array) @scandir($path) as $inner) {
            if (!is_string($inner) || substr($inner, -4) !== '.php') {
                continue;
            }
            $name = header_value($path . '/' . $inner, 'Plugin Name');
            if ($name === null) {
                continue;
            }
            $found++;
            printf("  %-34s %-10s %s\n", $entry, header_value($path . '/' . $inner, 'Version') ?? '?', $name);
            break;
        }
    }
    row('plugins with headers', $found);

    section('Installed themes');
    $themeDir = $contentRoot . '/themes';
    $found = 0;
    foreach ((array) @scandir($themeDir) as $entry) {
        if (!is_string($entry) || $entry === '.' || $entry === '..' || !is_dir($themeDir . '/' . $entry)) {
            continue;
        }
        $style = $themeDir . '/' . $entry . '/style.css';
        if (!is_file($style)) {
            continue;
        }
        $name = header_value($style, 'Theme Name');
        if ($name === null) {
            continue;
        }
        $found++;
        printf("  %-34s %-10s %s\n", $entry, header_value($style, 'Version') ?? '?', $name);
    }
    row('themes with headers', $found);
}

/* ------------------------------------------------------- unserialize ---- */

section('unserialize() call sites');

$patterns = [
    'unserialize(' => '/\bunserialize\s*\(/i',
    'maybe_unserialize(' => '/\bmaybe_unserialize\s*\(/i',
    'wrapped' => '/unserialize\s*\(\s*(?:base64_decode|stripslashes|urldecode|gzinflate|gzuncompress|hex2bin)/i',
];
$superglobal = '/\$_(?:GET|POST|COOKIE|REQUEST|FILES)\b/';

$counts = array_fill_keys(array_keys($patterns), 0);
$counts['files also reading superglobals'] = 0;
$hits = [];
$exposed = [];
$files = 0;
$maxHits = 120;
$maxExposed = 40;

$limit = (int) ini_get('max_execution_time');
$budget = $limit > 0 ? max(5, $limit - 5) : 25;
$budget = min($budget, 25);
$started = microtime(true);
$complete = true;

if ($contentRoot !== null) {
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($contentRoot, FilesystemIterator::SKIP_DOTS)
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
        $relative = str_replace($contentRoot, 'wp-content', $file->getPathname());
        $hasUnserialize = false;
        foreach ($patterns as $name => $regex) {
            if (!preg_match_all($regex, $source, $m)) {
                continue;
            }
            $hasUnserialize = true;
            $counts[$name] += count($m[0]);
            if (count($hits) < $maxHits) {
                $hits[] = $relative . '  [' . $name . ']';
            }
        }
        if ($hasUnserialize && preg_match($superglobal, $source)) {
            $counts['files also reading superglobals']++;
            if (count($exposed) < $maxExposed) {
                $exposed[] = $relative;
            }
        }
    }

    row('php files scanned', $files);
    row('scan completed', $complete ? 'yes' : 'NO - budget ' . $budget . 's reached, re-run to continue');
    foreach ($counts as $name => $count) {
        row($name, $count);
    }

    echo "\n-- files that unserialize AND read a superglobal (eyeball these) --\n";
    if ($exposed === []) {
        echo "   none\n";
    } else {
        echo '   ', implode("\n   ", $exposed), "\n";
        if (count($exposed) >= $maxExposed) {
            echo '   (truncated at ', $maxExposed, ")\n";
        }
    }

    echo "\n-- every call site --\n";
    if ($hits === []) {
        echo "   none\n";
    } else {
        echo '   ', implode("\n   ", array_unique($hits)), "\n";
        if (count($hits) >= $maxHits) {
            echo '   (truncated at ', $maxHits, ")\n";
        }
    }
}

echo "\nDone. Delete this file now.\n";
