<?php
// Set a default timezone to avoid potential warnings
date_default_timezone_set('UTC');
// It's better to configure this in php.ini, but for a single script, this is fine.
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

// ============================================================================
// CONSTANTS
// ============================================================================

/** The URL of the Base64 encoded subscription file. */
const GITHUB_SUB_URL = 'https://raw.githubusercontent.com/itsyebekhe/PSG/main/subscriptions/xray/base64/mix';

/** The root directory for all generated subscription files. */
const OUTPUT_DIR = 'subscriptions';

/** Timeout in seconds for each individual port check. */
const PORT_CHECK_TIMEOUT = 3;

/** How many ports to check concurrently in a single batch. */
const PARALLEL_BATCH_SIZE = 200;

/** The number of fastest proxies to select from each category for the combined link. */
const TOP_N_PROXIES = 15;


// ============================================================================
// UTILITY FUNCTIONS (Unchanged)
// ============================================================================

function is_ip(string $string): bool { return filter_var($string, FILTER_VALIDATE_IP) !== false; }
function parse_key_value_string(string $input): array { $data = []; $lines = preg_split('/\\R/', $input, -1, PREG_SPLIT_NO_EMPTY); foreach ($lines as $line) { $parts = explode('=', $line, 2); if (count($parts) === 2) { $key = trim($parts[0]); $value = trim($parts[1]); if ($key !== '' && $value !== '') { $data[$key] = $value; } } } return $data; }
function ip_info(string $ipOrHost): ?stdClass { return (object)["country" => "XX"]; }
function is_cloudflare_ip(string $ip, string $cacheFile = 'cloudflare_ips.json', int $cacheDuration = 86400): bool { return false; }
function ip_in_cidr(string $ip, string $cidr): bool { if (strpos($cidr, '/') === false) { return $ip === $cidr; } list($net, $mask) = explode('/', $cidr); $ip_net = inet_pton($ip); $net_net = inet_pton($net); if ($ip_net === false || $net_net === false) { return false; } if (strlen($ip_net) !== strlen($net_net)) { return false; } $mask_bin = str_repeat('1', $mask) . str_repeat('0', (strlen($ip_net) * 8) - $mask); $mask_net = ''; foreach (str_split($mask_bin, 8) as $byte) { $mask_net .= chr(bindec($byte)); } return ($ip_net & $mask_net) === ($net_net & $mask_net); }
function is_valid(string $input): bool { return !(str_contains($input, '…') || str_contains($input, '...')); }
function isEncrypted(string $input): bool { $configType = detect_type($input); switch ($configType) { case 'vmess': $decodedConfig = configParse($input); return ($decodedConfig['tls'] ?? '') !== '' && ($decodedConfig['scy'] ?? 'none') !== 'none'; case 'vless': case 'trojan': return str_contains($input, 'security=tls') || str_contains($input, 'security=reality'); case 'ss': case 'tuic': case 'hy2': return true; default: return false; } }
function getFlags(string $country_code): string { $country_code = strtoupper(trim($country_code)); if (strlen($country_code) !== 2 || !ctype_alpha($country_code) || $country_code === "XX") { return '🏳️'; } $regional_offset = 127397; $char1 = mb_convert_encoding('&#' . ($regional_offset + ord($country_code[0])) . ';', 'UTF-8', 'HTML-ENTITIES'); $char2 = mb_convert_encoding('&#' . ($regional_offset + ord($country_code[1])) . ';', 'UTF-8', 'HTML-ENTITIES'); return $char1 . $char2; }
function detect_type(string $input): ?string { if (str_starts_with($input, 'vmess://')) return 'vmess'; if (str_starts_with($input, 'vless://')) return 'vless'; if (str_starts_with($input, 'trojan://')) return 'trojan'; if (str_starts_with($input, 'ss://')) return 'ss'; if (str_starts_with($input, 'tuic://')) return 'tuic'; if (str_starts_with($input, 'hy2://') || str_starts_with($input, 'hysteria2://')) return 'hy2'; if (str_starts_with($input, 'hysteria://')) return 'hysteria'; return null; }
function extractLinksByType(string $text): array { $valid_types = ['vmess', 'vless', 'trojan', 'ss', 'tuic', 'hy2', 'hysteria']; $type_pattern = implode('|', $valid_types); $pattern = "/(?:{$type_pattern}):\\/\\/[^\\s\"']*(?=\\s|<|>|$)/i"; preg_match_all($pattern, $text, $matches); return $matches[0] ?? []; }
function configParse(string $input): ?array { $configType = detect_type($input); switch ($configType) { case 'vmess': return json_decode(base64_decode(substr($input, 8)), true); case 'vless': case 'trojan': case 'tuic': case 'hy2': $parsedUrl = parse_url($input); if ($parsedUrl === false) return null; $params = []; if (isset($parsedUrl['query'])) { parse_str($parsedUrl['query'], $params); } $output = ['protocol' => $configType, 'username' => $parsedUrl['user'] ?? '', 'hostname' => $parsedUrl['host'] ?? '', 'port' => $parsedUrl['port'] ?? '', 'params' => $params, 'hash' => isset($parsedUrl['fragment']) ? rawurldecode($parsedUrl['fragment']) : '']; if ($configType === 'tuic') { $output['pass'] = $parsedUrl['pass'] ?? ''; } return $output; case 'ss': $parsedUrl = parse_url($input); if ($parsedUrl === false) return null; $userInfo = rawurldecode($parsedUrl['user'] ?? ''); if (isBase64($userInfo)) { $userInfo = base64_decode($userInfo); } if (!str_contains($userInfo, ':')) return null; list($method, $password) = explode(':', $userInfo, 2); return ['encryption_method' => $method, 'password' => $password, 'server_address' => $parsedUrl['host'] ?? '', 'server_port' => $parsedUrl['port'] ?? '', 'name' => isset($parsedUrl['fragment']) ? rawurldecode($parsedUrl['fragment']) : '']; default: return null; } }
function reparseConfig(array $configArray, string $configType): ?string { return null; }
function is_reality(string $input): bool { return str_starts_with($input, 'vless://') && str_contains($input, 'security=reality'); }
function isBase64(string $input): bool { return base64_decode($input, true) !== false; }
function getRandomName(int $length = 10): string { $alphabet = 'abcdefghijklmnopqrstuvwxyz'; $max = strlen($alphabet) - 1; $name = ''; for ($i = 0; $i < $length; $i++) { try { $name .= $alphabet[random_int(0, $max)]; } catch (Exception $e) { $name .= $alphabet[mt_rand(0, $max)]; } } return $name; }
function deleteFolder(string $folder): bool { if (!is_dir($folder)) { return false; } $iterator = new RecursiveDirectoryIterator($folder, RecursiveDirectoryIterator::SKIP_DOTS); $files = new RecursiveIteratorIterator($iterator, RecursiveIteratorIterator::CHILD_FIRST); foreach ($files as $file) { if ($file->isDir()) { rmdir($file->getRealPath()); } else { unlink($file->getRealPath()); } } return rmdir($folder); }
function tehran_time(string $format = 'Y-m-d H:i:s'): string { try { $date = new DateTime('now', new DateTimeZone('Asia/Tehran')); return $date->format($format); } catch (Exception $e) { return date($format); } }
function hiddifyHeader(string $subscriptionName): string { $base64Name = base64_encode($subscriptionName); return <<<HEADER
#profile-title: base64:{$base64Name}
#profile-update-interval: 1
#subscription-userinfo: upload=0; download=0; total=10737418240000000; expire=2546249531
#support-url: https://t.me/yebekhe
#profile-web-page-url: https://github.com/itsyebekhe/PSG
HEADER;
}
function print_progress(int $current, int $total, string $message = ''): void { if (php_sapi_name() !== 'cli') return; if ($total == 0) return; $percentage = ($current / $total) * 100; $bar_length = 50; $filled_length = (int)($bar_length * $current / $total); $bar = str_repeat('=', $filled_length) . str_repeat(' ', $bar_length - $filled_length); printf("\r%s [%s] %d%% (%d/%d)", $message, $bar, $percentage, $current, $total); }
function is_valid_uuid(?string $uuid): bool { if ($uuid === null) { return false; } $pattern = '/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i'; return (bool) preg_match($pattern, $uuid); }

// ============================================================================
// PARALLEL HEALTH CHECK FUNCTION (MODIFIED FOR LATENCY)
// ============================================================================

function check_ports_parallel(array $proxies): array {
    $liveConfigs = [];
    $proxyData = [];
    foreach ($proxies as $config) {
        $wrapper = new ConfigWrapper($config);
        if ($wrapper->isValid()) {
            $server = $wrapper->getServer();
            $port = $wrapper->getPort();
            if (!empty($server) && $port > 0) {
                $proxyData[] = ['host' => $server, 'port' => $port, 'config' => $config];
            }
        }
    }
    $totalToCheck = count($proxyData);
    $checkedCount = 0;
    $batches = array_chunk($proxyData, PARALLEL_BATCH_SIZE);
    foreach ($batches as $batch) {
        $sockets = [];
        $socketData = [];
        $write = [];
        foreach ($batch as $details) {
            $socket = @stream_socket_client("tcp://{$details['host']}:{$details['port']}", $errno, $errstr, null, STREAM_CLIENT_CONNECT | STREAM_CLIENT_ASYNC_CONNECT);
            if ($socket) {
                $socketId = (int)$socket;
                $sockets[$socketId] = $socket;
                $socketData[$socketId] = ['config' => $details['config'], 'startTime' => microtime(true)];
                $write[$socketId] = $socket;
            } else {
                $checkedCount++;
            }
        }
        while (!empty($write)) {
            $w = $write; $r = null; $e = null;
            $num = @stream_select($r, $w, $e, PORT_CHECK_TIMEOUT);
            if ($num === false) break;
            foreach ($w as $socket) {
                $socketId = (int)$socket;
                $latency = (microtime(true) - $socketData[$socketId]['startTime']) * 1000;
                $liveConfigs[] = ['config' => $socketData[$socketId]['config'], 'latency' => (int)$latency];
                fclose($socket);
                unset($write[$socketId], $sockets[$socketId]);
                $checkedCount++;
            }
            $now = microtime(true);
            foreach ($write as $socketId => $socket) {
                if (($now - $socketData[$socketId]['startTime']) > PORT_CHECK_TIMEOUT) {
                    fclose($socket);
                    unset($write[$socketId], $sockets[$socketId]);
                    $checkedCount++;
                }
            }
            print_progress($checkedCount, $totalToCheck, "Checking ports: ");
        }
        foreach ($sockets as $socket) { fclose($socket); }
    }
    return $liveConfigs;
}

// ============================================================================
// CONFIG WRAPPER CLASS (Unchanged)
// ============================================================================

class ConfigWrapper {
    private ?array $decoded; private string $type;
    public function __construct(string $config_string) { $this->type = detect_type($config_string) ?? 'unknown'; $this->decoded = configParse($config_string); }
    public function isValid(): bool { return $this->decoded !== null; }
    public function getType(): string { return $this->type; }
    public function getServer(): string { return match($this->type) { 'vmess' => $this->decoded['add'], 'ss' => $this->decoded['server_address'], default => $this->decoded['hostname'], }; }
    public function getPort(): int { return (int)(match($this->type) { 'ss' => $this->decoded['server_port'], default => $this->decoded['port'], }); }
    public function getTag(): string { return ''; } public function getUuid(): string { return ''; } public function getPassword(): string { return ''; } public function getSni(): string { return ''; } public function getTransportType(): ?string { return null; } public function getPath(): string { return ''; } public function getServiceName(): string { return ''; } public function get(string $key, $default = null) { return $this->decoded[$key] ?? $default; } public function getParam(string $key, $default = null) { return $this->decoded['params'][$key] ?? $default; }
}

// ============================================================================
// MAIN EXECUTION LOGIC (WITH REVISED NAMING STRATEGY)
// ============================================================================

function main()
{
    echo "Starting proxy fetch and check process...\n";

    echo "  - Fetching subscription file from GitHub...\n";
    $base64Content = @file_get_contents(GITHUB_SUB_URL);
    if ($base64Content === false) { echo "[ERROR] Failed to download the subscription file.\n"; exit(1); }

    $decodedContent = base64_decode($base64Content);
    if ($decodedContent === false) { echo "[ERROR] Failed to decode the subscription file.\n"; exit(1); }

    $allConfigs = preg_split('/\\R/', $decodedContent, -1, PREG_SPLIT_NO_EMPTY);
    if (empty($allConfigs)) { echo "[WARNING] No proxy configurations found.\n"; exit(0); }
    echo "  - Found " . count($allConfigs) . " configs. Starting parallel health checks...\n";

    $liveConfigsWithLatency = check_ports_parallel($allConfigs);
    echo "\n  - Health check complete. Found " . count($liveConfigsWithLatency) . " live proxies.\n";

    // --- 1. Categorize and Sort Proxies ---
    $categorizedConfigs = [];
    foreach ($liveConfigsWithLatency as $proxyInfo) {
        $type = detect_type($proxyInfo['config']);
        if ($type) {
            $categorizedConfigs[$type][] = $proxyInfo;
        }
    }
    ksort($categorizedConfigs);

    // --- 2. Create Directory Structure ---
    echo "  - Preparing output directory structure...\n";
    $baseDir = OUTPUT_DIR;
    $dirs = [
        "{$baseDir}/by_type/plaintext",
        "{$baseDir}/by_type/base64",
        "{$baseDir}/combined/plaintext",
        "{$baseDir}/combined/base64",
    ];
    foreach ($dirs as $dir) {
        if (!is_dir($dir)) {
            mkdir($dir, 0755, true);
        }
    }

    // --- 3. Save "by_type" Files ---
    $topFastestProxies = [];
    $summaryDataByType = [];
    echo "  - Saving subscriptions categorized by type...\n";
    foreach ($categorizedConfigs as $type => $proxies) {
        usort($proxies, fn($a, $b) => $a['latency'] <=> $b['latency']);
        
        $topFastestProxies = array_merge($topFastestProxies, array_slice($proxies, 0, TOP_N_PROXIES));
        $summaryDataByType[$type] = count($proxies);

        $allConfigsForType = array_column($proxies, 'config');
        $normalContent = implode("\n", $allConfigsForType);
        $base64Content = base64_encode($normalContent);
        
        file_put_contents("{$dirs[0]}/{$type}.txt", $normalContent);
        file_put_contents("{$dirs[1]}/{$type}.txt", $base64Content);
        echo "    - Saved {$type} (" . count($proxies) . " configs)\n";
    }

    // --- 4. Save "combined" Files ---
    echo "  - Saving combined subscription files...\n";

    // Sort all live proxies by latency for the "all_live" file
    usort($liveConfigsWithLatency, fn($a, $b) => $a['latency'] <=> $b['latency']);
    $allLiveConfigs = array_column($liveConfigsWithLatency, 'config');
    file_put_contents("{$dirs[2]}/all_live.txt", implode("\n", $allLiveConfigs));
    file_put_contents("{$dirs[3]}/all_live.txt", base64_encode(implode("\n", $allLiveConfigs)));
    echo "    - Saved all_live.txt (" . count($allLiveConfigs) . " configs)\n";

    // Sort the collected top proxies by latency for the "top_fastest" file
    usort($topFastestProxies, fn($a, $b) => $a['latency'] <=> $b['latency']);
    $topConfigs = array_column($topFastestProxies, 'config');
    file_put_contents("{$dirs[2]}/top_fastest.txt", implode("\n", $topConfigs));
    file_put_contents("{$dirs[3]}/top_fastest.txt", base64_encode(implode("\n", $topConfigs)));
    echo "    - Saved top_fastest.txt (" . count($topConfigs) . " configs)\n";

    // --- 5. Create Summary File ---
    $summary = [
        'generated_at' => date('c'),
        'proxies_found_in_source' => count($allConfigs),
        'live_proxies_found' => count($liveConfigsWithLatency),
        'live_proxies_by_type' => $summaryDataByType,
    ];
    file_put_contents("{$baseDir}/summary.json", json_encode($summary, JSON_PRETTY_PRINT));
    echo "  - Generated summary.json\n";
    
    echo "\nProcess finished successfully!\n";
    echo "Subscription files are saved in the '" . OUTPUT_DIR . "' directory.\n";
}

main();