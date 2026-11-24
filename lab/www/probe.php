<?php
// SPDX-License-Identifier: MIT
// Copyright (c) 2026 GG ADVANCED IT Security UG

// probe.php - diagnostic endpoint for the lab, never a target of the chain.
//
// The arming request works by making PHP build very large nested arrays from multipart field names.
// When a build refuses to arm, the useful question is not "did it crash" but "what did it actually
// build", and that is what this prints: how many POST variables survived, how deep the nesting went,
// how much memory the request needed, and whether the engine complained about any limit.
//
//   curl -s 'http://127.0.0.1:18120/probe.php' -F 'PHPSESSID=aa' ... (any multipart body)
error_reporting(E_ALL);
$deepest = 0;
$count = 0;
$walk = function ($value, $depth) use (&$walk, &$deepest, &$count) {
    $count++;
    if ($depth > $deepest) {
        $deepest = $depth;
    }
    if (is_array($value)) {
        foreach ($value as $item) {
            $walk($item, $depth + 1);
        }
    }
};
$walk($_POST, 0);
// Distribution of a package build, e.g. "debian13". Part of the offset-profile key: the same PHP
// version from a different packager is a different libphp with different offsets.
$os_release = @file_get_contents('/etc/os-release') ?: '';
preg_match('/^ID="?([a-z0-9]+)"?$/m', $os_release, $os_id);
preg_match('/^VERSION_ID="?([0-9]+)"?$/m', $os_release, $os_ver);
echo json_encode([
    'php' => PHP_VERSION,
    'sapi' => php_sapi_name(),
    'arch' => php_uname('m'),
    'os' => php_uname('s'),
    'distro' => ($os_id[1] ?? '') . ($os_ver[1] ?? ''),
    'pid' => getmypid(),
    'post_top_level' => count($_POST),
    'post_nodes' => $count,
    'post_depth' => $deepest,
    'files' => count($_FILES),
    // memory_get_peak_usage(true) reports *allocated chunks*, which Zend keeps between requests, so it
    // moves down as well as up and cannot answer "how close is the heap to the limit". The non-real
    // figures count the bytes PHP actually asked for, which is the signal a size search needs.
    'memory_usage' => memory_get_usage(),
    'memory_usage_real' => memory_get_usage(true),
    'memory_peak' => memory_get_peak_usage(),
    'memory_limit' => ini_get('memory_limit'),
    'post_max_size' => ini_get('post_max_size'),
    'display_errors' => ini_get('display_errors'),
    'session.upload_progress.cleanup' => ini_get('session.upload_progress.cleanup'),
    'session_status' => session_status(),
    'max_input_vars' => ini_get('max_input_vars'),
    'max_multipart_body_parts' => ini_get('max_multipart_body_parts'),
    'upload_progress' => ini_get('session.upload_progress.enabled'),
], JSON_PRETTY_PRINT), "\n";
