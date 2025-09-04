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

/** The directory where sorted subscription files will be saved. */
const OUTPUT_DIR = 'sorted_subscriptions';

/** Timeout in seconds for the port check. */
const PORT_CHECK_TIMEOUT = 2;


// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * Validates if a string is a valid IP address (IPv4 or IPv6).
 */
function is_ip(string $string): bool
{
    return filter_var($string, FILTER_VALIDATE_IP) !== false;
}

/**
 * Parses a key-value string into an associative array.
 */
function parse_key_value_string(string $input): array
{
    $data = [];
    $lines = preg_split('/\\R/', $input, -1, PREG_SPLIT_NO_EMPTY);

    foreach ($lines as $line) {
        $parts = explode('=', $line, 2);
        if (count($parts) === 2) {
            $key = trim($parts[0]);
            $value = trim($parts[1]);
            if ($key !== '' && $value !== '') {
                $data[$key] = $value;
            }
        }
    }
    return $data;
}

/**
 * Gets geolocation information for an IP or hostname.
 */
function ip_info(string $ipOrHost): ?stdClass
{
    $ip = $ipOrHost;
    if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
        $ip_records = @dns_get_record($ip, DNS_A);
        if (empty($ip_records)) {
            return null;
        }
        $ip = $ip_records[array_rand($ip_records)]["ip"];
    }

    if (is_cloudflare_ip($ip)) {
        return (object)["country" => "CF"];
    }
    
    $endpoints = [
        ['https://ipapi.co/{ip}/json/', 'country_code'],
        ['https://ipwho.is/{ip}', 'country_code'],
        ['http://www.geoplugin.net/json.gp?ip={ip}', 'geoplugin_countryCode'],
    ];

    $options = [
        'http' => [
            'method' => 'GET',
            'header' => "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36\r\n",
            'timeout' => 3,
            'ignore_errors' => true,
        ],
    ];
    $context = stream_context_create($options);

    foreach ($endpoints as [$url_template, $country_key]) {
        $url = str_replace('{ip}', urlencode($ip), $url_template);
        $response = @file_get_contents($url, false, $context);

        if ($response !== false) {
            $data = json_decode($response);
            if (json_last_error() === JSON_ERROR_NONE && isset($data->{$country_key})) {
                return (object)["country" => $data->{$country_key} ?? 'XX'];
            }
        }
    }

    return (object)["country" => "XX"];
}

/**
 * Checks if a given IP address belongs to Cloudflare.
 */
function is_cloudflare_ip(string $ip, string $cacheFile = 'cloudflare_ips.json', int $cacheDuration = 86400): bool
{
    if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
        return false;
    }

    $ipRanges = [];

    if (file_exists($cacheFile) && (time() - filemtime($cacheFile)) < $cacheDuration) {
        $ipRanges = json_decode(file_get_contents($cacheFile), true);
    } else {
        $ipv4 = @file_get_contents('https://www.cloudflare.com/ips-v4');
        $ipv6 = @file_get_contents('https://www.cloudflare.com/ips-v6');

        if ($ipv4 && $ipv6) {
            $ipv4Ranges = explode("\n", trim($ipv4));
            $ipv6Ranges = explode("\n", trim($ipv6));
            $ipRanges = array_merge($ipv4Ranges, $ipv6Ranges);
            file_put_contents($cacheFile, json_encode($ipRanges));
        } else if (file_exists($cacheFile)) {
            $ipRanges = json_decode(file_get_contents($cacheFile), true);
        }
    }

    if (empty($ipRanges)) {
        return false;
    }

    foreach ($ipRanges as $range) {
        if (ip_in_cidr($ip, $range)) {
            return true;
        }
    }

    return false;
}

/**
 * Helper function to check if an IP is within a CIDR range.
 */
function ip_in_cidr(string $ip, string $cidr): bool
{
    if (strpos($cidr, '/') === false) {
        return $ip === $cidr;
    }
    
    list($net, $mask) = explode('/', $cidr);

    $ip_net = inet_pton($ip);
    $net_net = inet_pton($net);
    
    if ($ip_net === false || $net_net === false) {
        return false;
    }

    $ip_len = strlen($ip_net);
    $net_len = strlen($net_net);

    if ($ip_len !== $net_len) {
        return false;
    }
    
    $mask_bin = str_repeat('1', $mask) . str_repeat('0', ($ip_len * 8) - $mask);
    $mask_net = '';
    foreach (str_split($mask_bin, 8) as $byte) {
        $mask_net .= chr(bindec($byte));
    }

    return ($ip_net & $mask_net) === ($net_net & $mask_net);
}

/**
 * Checks if the input string contains invalid characters.
 */
function is_valid(string $input): bool
{
    return !(str_contains($input, '…') || str_contains($input, '...'));
}

/**
 * Determines if a proxy configuration is encrypted.
 */
function isEncrypted(string $input): bool
{
    $configType = detect_type($input);

    switch ($configType) {
        case 'vmess':
            $decodedConfig = configParse($input);
            return ($decodedConfig['tls'] ?? '') !== '' && ($decodedConfig['scy'] ?? 'none') !== 'none';

        case 'vless':
        case 'trojan':
            return str_contains($input, 'security=tls') || str_contains($input, 'security=reality');
        
        case 'ss':
        case 'tuic':
        case 'hy2':
            return true;

        default:
            return false;
    }
}

/**
 * Converts a 2-letter country code to a regional flag emoji.
 */
function getFlags(string $country_code): string
{
    $country_code = strtoupper(trim($country_code));
    if (strlen($country_code) !== 2 || !ctype_alpha($country_code) || $country_code === "XX") {
        return '🏳️';
    }

    $regional_offset = 127397;
    $char1 = mb_convert_encoding('&#' . ($regional_offset + ord($country_code[0])) . ';', 'UTF-8', 'HTML-ENTITIES');
    $char2 = mb_convert_encoding('&#' . ($regional_offset + ord($country_code[1])) . ';', 'UTF-8', 'HTML-ENTITIES');
    
    return $char1 . $char2;
}

/**
 * Detects the proxy protocol type from a configuration link.
 */
function detect_type(string $input): ?string
{
    if (str_starts_with($input, 'vmess://')) return 'vmess';
    if (str_starts_with($input, 'vless://')) return 'vless';
    if (str_starts_with($input, 'trojan://')) return 'trojan';
    if (str_starts_with($input, 'ss://')) return 'ss';
    if (str_starts_with($input, 'tuic://')) return 'tuic';
    if (str_starts_with($input, 'hy2://') || str_starts_with($input, 'hysteria2://')) return 'hy2';
    if (str_starts_with($input, 'hysteria://')) return 'hysteria';
    
    return null;
}

/**
 * Extracts all valid proxy links from a given text.
 */
function extractLinksByType(string $text): array
{
    $valid_types = ['vmess', 'vless', 'trojan', 'ss', 'tuic', 'hy2', 'hysteria'];
    $type_pattern = implode('|', $valid_types);
    $pattern = "/(?:{$type_pattern}):\\/\\/[^\\s\"']*(?=\\s|<|>|$)/i";
    
    preg_match_all($pattern, $text, $matches);
    
    return $matches[0] ?? [];
}

/**
 * Parses a configuration link into an associative array.
 */
function configParse(string $input): ?array
{
    $configType = detect_type($input);

    switch ($configType) {
        case 'vmess':
            $base64_data = substr($input, 8);
            return json_decode(base64_decode($base64_data), true);

        case 'vless':
        case 'trojan':
        case 'tuic':
        case 'hy2':
            $parsedUrl = parse_url($input);
            if ($parsedUrl === false) return null;
            
            $params = [];
            if (isset($parsedUrl['query'])) {
                parse_str($parsedUrl['query'], $params);
            }
            
            $output = [
                'protocol' => $configType,
                'username' => $parsedUrl['user'] ?? '',
                'hostname' => $parsedUrl['host'] ?? '',
                'port' => $parsedUrl['port'] ?? '',
                'params' => $params,
                'hash' => isset($parsedUrl['fragment']) ? rawurldecode($parsedUrl['fragment']) : 'PSG' . getRandomName(),
            ];

            if ($configType === 'tuic') {
                $output['pass'] = $parsedUrl['pass'] ?? '';
            }
            return $output;

        case 'ss':
            $parsedUrl = parse_url($input);
            if ($parsedUrl === false) return null;

            $userInfo = rawurldecode($parsedUrl['user'] ?? '');
            if (isBase64($userInfo)) {
                $userInfo = base64_decode($userInfo);
            }

            if (!str_contains($userInfo, ':')) return null;
            list($method, $password) = explode(':', $userInfo, 2);

            return [
                'encryption_method' => $method,
                'password' => $password,
                'server_address' => $parsedUrl['host'] ?? '',
                'server_port' => $parsedUrl['port'] ?? '',
                'name' => isset($parsedUrl['fragment']) ? rawurldecode($parsedUrl['fragment']) : 'PSG' . getRandomName(),
            ];
            
        default:
            return null;
    }
}

/**
 * Rebuilds a configuration link from a parsed array.
 */
function reparseConfig(array $configArray, string $configType): ?string
{
    switch ($configType) {
        case 'vmess':
            $encoded_data = rtrim(strtr(base64_encode(json_encode($configArray)), '+/', '-_'), '=');
            return "vmess://" . $encoded_data;
        
        case 'vless':
        case 'trojan':
        case 'tuic':
        case 'hy2':
            $url = $configType . "://";
            if (!empty($configArray['username'])) {
                $url .= $configArray['username'];
                if (!empty($configArray['pass'])) {
                    $url .= ':' . $configArray['pass'];
                }
                $url .= '@';
            }
            $url .= $configArray['hostname'];
            if (!empty($configArray['port'])) {
                $url .= ':' . $configArray['port'];
            }
            if (!empty($configArray['params'])) {
                $url .= '?' . http_build_query($configArray['params']);
            }
            if (!empty($configArray['hash'])) {
                $url .= '#' . rawurlencode($configArray['hash']);
            }
            return $url;

        case 'ss':
            $user_info = base64_encode($configArray['encryption_method'] . ':' . $configArray['password']);
            $url = "ss://{$user_info}@{$configArray['server_address']}:{$configArray['server_port']}";
            if (!empty($configArray['name'])) {
                $url .= '#' . rawurlencode($configArray['name']);
            }
            return $url;

        default:
            return null;
    }
}

/**
 * Checks if a VLESS config uses the 'reality' security protocol.
 */
function is_reality(string $input): bool
{
    return str_starts_with($input, 'vless://') && str_contains($input, 'security=reality');
}

/**
 * Checks if a string is Base64 encoded.
 */
function isBase64(string $input): bool
{
    return base64_decode($input, true) !== false;
}

/**
 * Generates a cryptographically secure random name.
 */
function getRandomName(int $length = 10): string
{
    $alphabet = 'abcdefghijklmnopqrstuvwxyz';
    $max = strlen($alphabet) - 1;
    $name = '';
    for ($i = 0; $i < $length; $i++) {
        $name .= $alphabet[random_int(0, $max)];
    }
    return $name;
}

/**
 * Recursively deletes a folder and its contents.
 */
function deleteFolder(string $folder): bool
{
    if (!is_dir($folder)) {
        return false;
    }

    $iterator = new RecursiveDirectoryIterator($folder, RecursiveDirectoryIterator::SKIP_DOTS);
    $files = new RecursiveIteratorIterator($iterator, RecursiveIteratorIterator::CHILD_FIRST);

    foreach ($files as $file) {
        if ($file->isDir()) {
            rmdir($file->getRealPath());
        } else {
            unlink($file->getRealPath());
        }
    }

    return rmdir($folder);
}

/**
 * Gets the current time in the Asia/Tehran timezone.
 */
function tehran_time(string $format = 'Y-m-d H:i:s'): string
{
    try {
        $date = new DateTime('now', new DateTimeZone('Asia/Tehran'));
        return $date->format($format);
    } catch (Exception $e) {
        return date($format);
    }
}

/**
 * Generates a Hiddify-compatible subscription header.
 */
function hiddifyHeader(string $subscriptionName): string
{
    $base64Name = base64_encode($subscriptionName);
    return <<<HEADER
#profile-title: base64:{$base64Name}
#profile-update-interval: 1
#subscription-userinfo: upload=0; download=0; total=10737418240000000; expire=2546249531
#support-url: https://t.me/yebekhe
#profile-web-page-url: https://github.com/itsyebekhe/PSG

HEADER;
}

/**
 * INTERNAL FUNCTION: Fetches a single batch of URLs in parallel.
 */
function _internal_fetch_batch(array $urls): array
{
    $multi_handle = curl_multi_init();
    $handles = [];
    $results = [];

    if (empty($urls)) {
        return [];
    }

    foreach ($urls as $key => $url) {
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS => 5,
            CURLOPT_TIMEOUT => 20,
            CURLOPT_CONNECTTIMEOUT => 10,
            CURLOPT_USERAGENT => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36',
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_SSL_VERIFYHOST => false,
        ]);
        $handles[$key] = $ch;
        curl_multi_add_handle($multi_handle, $ch);
    }

    $running = null;
    do {
        curl_multi_exec($multi_handle, $running);
        if ($running) {
            curl_multi_select($multi_handle);
        }
    } while ($running > 0);

    foreach ($handles as $key => $ch) {
        $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $content = curl_multi_getcontent($ch);
        
        if (curl_errno($ch) === 0 && $http_code === 200 && !empty($content)) {
            $results[$key] = $content;
        }
        
        curl_multi_remove_handle($multi_handle, $ch);
        curl_close($ch);
    }

    curl_multi_close($multi_handle);
    return $results;
}

/**
 * PUBLIC FUNCTION: Fetches multiple URLs in parallel with a retry mechanism.
 */
function fetch_multiple_urls_parallel(array $urls, int $max_retries = 3, int $delay = 2): array
{
    $all_fetched_content = [];
    $urls_to_retry = $urls;

    for ($attempt = 1; $attempt <= $max_retries; $attempt++) {
        if (empty($urls_to_retry)) {
            break;
        }

        echo "\n  - Fetch attempt #{$attempt} for " . count($urls_to_retry) . " URLs...";
        
        $fetched_this_round = _internal_fetch_batch($urls_to_retry);
        $all_fetched_content = array_merge($all_fetched_content, $fetched_this_round);
        $urls_to_retry = array_diff_key($urls_to_retry, $fetched_this_round);

        if (!empty($urls_to_retry) && $attempt < $max_retries) {
            echo PHP_EOL . "  [!] " . count($urls_to_retry) . " URLs failed. Retrying in {$delay} seconds..." . PHP_EOL;
            sleep($delay);
        }
    }
    
    if (!empty($urls_to_retry)) {
        echo PHP_EOL . "  [!!] CRITICAL WARNING: The following URLs failed after all attempts:" . PHP_EOL;
        foreach (array_keys($urls_to_retry) as $failed_key) {
            echo "      - {$failed_key}" . PHP_EOL;
        }
    }

    return $all_fetched_content;
}

/**
 * Prints a clean, overwriting progress bar to the console.
 */
function print_progress(int $current, int $total, string $message = ''): void
{
    if (php_sapi_name() !== 'cli') return;
    if ($total == 0) return;
    $percentage = ($current / $total) * 100;
    $bar_length = 50;
    $filled_length = (int)($bar_length * $current / $total);
    $bar = str_repeat('=', $filled_length) . str_repeat(' ', $bar_length - $filled_length);
    printf("\r%s [%s] %d%% (%d/%d)", $message, $bar, $percentage, $current, $total);
}

/**
 * Validates if a string is a valid Version 4 UUID.
 */
function is_valid_uuid(?string $uuid): bool
{
    if ($uuid === null) {
        return false;
    }
    
    $pattern = '/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i';
    return (bool) preg_match($pattern, $uuid);
}

/**
 * Fetches multiple pages of a Telegram channel.
 */
function fetch_channel_data_paginated(string $channelName, int $maxPages): string
{
    $combinedHtml = '';
    $nextUrl = "https://t.me/s/{$channelName}";
    $fetchedPages = 0;

    while ($fetchedPages < $maxPages && $nextUrl) {
        echo "\rFetching page " . ($fetchedPages + 1) . "/{$maxPages} for channel '{$channelName}'... ";
        
        $response = @file_get_contents($nextUrl, false, stream_context_create([
            'http' => [
                'timeout' => 15,
                'user_agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36',
            ]
        ]));

        if ($response === false || empty($response)) {
            $nextUrl = null;
            continue;
        }

        $combinedHtml .= $response;

        preg_match_all('/data-post="[^"]+\/(\d+)"/', $response, $matches);
        
        if (!empty($matches[1])) {
            $oldestMessageId = min($matches[1]);
            $nextUrl = "https://t.me/s/{$channelName}?before={$oldestMessageId}";
        } else {
            $nextUrl = null;
        }
        $fetchedPages++;
    }

    return $combinedHtml;
}

// ============================================================================
// NEW: HEALTH CHECK FUNCTION
// ============================================================================

/**
 * Checks if a TCP port is open on a given host.
 * This is a basic reachability test.
 *
 * @param string $host The server IP address or hostname.
 * @param int $port The port to check.
 * @param int $timeout The connection timeout in seconds.
 * @return bool True if the port is open, false otherwise.
 */
function is_port_open(string $host, int $port, int $timeout = PORT_CHECK_TIMEOUT): bool
{
    // stream_socket_client is generally preferred over fsockopen.
    // It respects the timeout for the connection phase.
    $socket = @stream_socket_client("tcp://{$host}:{$port}", $errno, $errstr, $timeout);

    if ($socket) {
        fclose($socket);
        return true;
    }

    return false;
}

// ============================================================================
// CONFIG WRAPPER CLASS
// ============================================================================

class ConfigWrapper
{
    private ?array $decoded;
    private string $type;

    public function __construct(string $config_string)
    {
        $this->type = detect_type($config_string) ?? 'unknown';
        $this->decoded = configParse($config_string);
    }

    public function isValid(): bool
    {
        return $this->decoded !== null;
    }

    public function getType(): string
    {
        return $this->type;
    }

    public function getTag(): string
    {
        $field = match($this->type) {
            'vmess' => 'ps',
            'ss' => 'name',
            default => 'hash',
        };
        return urldecode($this->decoded[$field] ?? 'Unknown Tag');
    }

    public function getServer(): string
    {
        return match($this->type) {
            'vmess' => $this->decoded['add'],
            'ss' => $this->decoded['server_address'],
            default => $this->decoded['hostname'],
        };
    }

    public function getPort(): int
    {
        $port = match($this->type) {
            'ss' => $this->decoded['server_port'],
            default => $this->decoded['port'],
        };
        return (int)$port;
    }

    public function getUuid(): string
    {
        return match($this->type) {
            'vmess' => $this->decoded['id'],
            'vless', 'trojan' => $this->decoded['username'],
            'tuic' => $this->decoded['username'],
            default => '',
        };
    }

    public function getPassword(): string
    {
        return match($this->type) {
            'trojan' => $this->decoded['username'],
            'ss' => $this->decoded['password'],
            'tuic' => $this->decoded['pass'],
            'hy2' => $this->decoded['username'],
            default => '',
        };
    }

    public function getSni(): string
    {
        return match($this->type) {
            'vmess' => $this->decoded['sni'] ?? $this->getServer(),
            default => $this->decoded['params']['sni'] ?? $this->getServer(),
        };
    }

    public function getTransportType(): ?string
    {
        return match($this->type) {
            'vmess' => $this->decoded['net'],
            default => $this->decoded['params']['type'] ?? null,
        };
    }
    
    public function getPath(): string
    {
        $path = match($this->type) {
            'vmess' => $this->decoded['path'] ?? '/',
            default => $this->decoded['params']['path'] ?? '/',
        };
        return '/' . ltrim($path, '/');
    }

    public function getServiceName(): string
    {
        return match($this->type) {
            'vmess' => $this->decoded['path'] ?? '',
            default => $this->decoded['params']['serviceName'] ?? '',
        };
    }

    public function get(string $key, $default = null)
    {
        return $this->decoded[$key] ?? $default;
    }
    
    public function getParam(string $key, $default = null)
    {
        return $this->decoded['params'][$key] ?? $default;
    }
}


// ============================================================================
// MAIN EXECUTION LOGIC
// ============================================================================

function main()
{
    echo "Starting proxy fetch and check process...\n";

    // 1. Fetch the subscription content from the URL
    echo "  - Fetching subscription file from GitHub...\n";
    $base64Content = @file_get_contents(GITHUB_SUB_URL);
    if ($base64Content === false) {
        echo "[ERROR] Failed to download the subscription file. Please check the URL and your internet connection.\n";
        exit(1);
    }

    // 2. Decode the content
    $decodedContent = base64_decode($base64Content);
    if ($decodedContent === false) {
        echo "[ERROR] Failed to decode the subscription file. It might not be valid Base64.\n";
        exit(1);
    }

    // 3. Split into individual configs
    $allConfigs = preg_split('/\\R/', $decodedContent, -1, PREG_SPLIT_NO_EMPTY);
    if (empty($allConfigs)) {
        echo "[WARNING] No proxy configurations found in the subscription file.\n";
        exit(0);
    }
    $totalConfigs = count($allConfigs);
    echo "  - Found {$totalConfigs} configs. Starting health checks...\n";

    // 4. Perform health checks
    $liveConfigs = [];
    $i = 0;
    foreach ($allConfigs as $configLink) {
        $i++;
        print_progress($i, $totalConfigs, "Checking ports: ");
        $wrapper = new ConfigWrapper($configLink);

        if ($wrapper->isValid()) {
            $server = $wrapper->getServer();
            $port = $wrapper->getPort();

            if (!empty($server) && $port > 0) {
                if (is_port_open($server, $port)) {
                    $liveConfigs[] = $configLink;
                }
            }
        }
    }
    echo "\n  - Health check complete. Found " . count($liveConfigs) . " live proxies.\n";

    // 5. Categorize and sort live configs by type
    $categorizedConfigs = [];
    foreach ($liveConfigs as $configLink) {
        $type = detect_type($configLink);
        if ($type) {
            $categorizedConfigs[$type][] = $configLink;
        }
    }
    // Sort by key (type name) for consistent file output order
    ksort($categorizedConfigs);

    // 6. Save the results to files
    if (!is_dir(OUTPUT_DIR)) {
        mkdir(OUTPUT_DIR, 0755, true);
    }

    echo "  - Saving sorted subscription files...\n";
    foreach ($categorizedConfigs as $type => $configs) {
        $normalContent = implode("\n", $configs);
        $base64Content = base64_encode($normalContent);

        $normalFile = OUTPUT_DIR . "/{$type}.txt";
        $base64File = OUTPUT_DIR . "/{$type}_base64.txt";

        file_put_contents($normalFile, $normalContent);
        file_put_contents($base64File, $base64Content);
        
        echo "    - Created {$type}.txt and {$type}_base64.txt (" . count($configs) . " configs)\n";
    }

    echo "\nProcess finished successfully!\n";
    echo "Live proxy files are saved in the '" . OUTPUT_DIR . "' directory.\n";
}

// Run the main function
main();
