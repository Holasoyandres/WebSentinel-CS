<?php

namespace WebSentinel\Http\Middleware;

use Closure;
use Symfony\Component\HttpFoundation\IpUtils;
use WebSentinel\Services\Normalizer;
use WebSentinel\Services\SentinelClient;
use WebSentinel\View\Components\Honeypot;

class WebSentinelFirewall
{
    protected SentinelClient $sentinel;
    protected array $signatures = [];

    public function __construct(SentinelClient $sentinel)
    {
        $this->sentinel = $sentinel;
        $this->loadSignatures();
    }

    /**
     * Intercept and audit incoming HTTP requests for threat vectors.
     *
     * @param mixed $request
     * @param \Closure $next
     * @return mixed
     */
    public function handle($request, Closure $next)
    {
        $clientIp = method_exists($request, 'ip') ? $request->ip() : '127.0.0.1';

        // 1. IP & CIDR Whitelist Check
        $whitelist = function_exists('config') ? config('websentinel.ip_whitelist', ['127.0.0.1', '::1']) : ['127.0.0.1', '::1'];
        if ($this->isIpWhitelisted($clientIp, $whitelist)) {
            return $next($request);
        }

        // 2. Excluded Routes Check
        $excludedRoutes = function_exists('config') ? config('websentinel.excluded_routes', []) : [];
        if (method_exists($request, 'is')) {
            foreach ($excludedRoutes as $excluded) {
                if ($request->is($excluded)) {
                    return $next($request);
                }
            }
        }

        $path = method_exists($request, 'path') ? $request->path() : '/';
        $mode = function_exists('config') ? config('websentinel.mode', 'block') : 'block';

        // 3. Automated Honeypot Bot Trap Evaluation
        $honeypotField = function_exists('config') ? config('websentinel.honeypot_field', 'websentinel_verification_token') : 'websentinel_verification_token';
        $timeField = function_exists('config') ? config('websentinel.honeypot_time_field', 'websentinel_ts') : 'websentinel_ts';

        $honeypotValue = method_exists($request, 'input') ? $request->input($honeypotField) : null;
        if (!empty($honeypotValue) && is_string($honeypotValue)) {
            $incidentId = 'SEC-' . $this->generateUuid();
            $this->sentinel->reportEvent([
                'type'     => 'BOT_TRAPPED',
                'severity' => 'HIGH',
                'ruleId'   => 'SIG-BOT-001',
                'sourceIp' => $clientIp,
                'target'   => $path,
                'details'  => 'Automated bot crawler filled hidden honeypot input field.',
                'action'   => $mode === 'block' ? 'BLOCKED' : 'FLAGGED'
            ]);

            if ($mode === 'block') {
                return $this->respondBlocked('Automated bot crawler activity trapped by honeypot.', 'SIG-BOT-001', 'CWE-799', $incidentId);
            }
        }

        // Sub-second submission verification (Speed Bot Defense)
        $timeToken = method_exists($request, 'input') ? $request->input($timeField) : null;
        if (!empty($timeToken) && is_string($timeToken)) {
            $minSeconds = function_exists('config') ? (int)config('websentinel.honeypot_min_time_seconds', 1) : 1;
            $validation = Honeypot::validateTimestampToken($timeToken, $minSeconds);

            if ($validation['isBot']) {
                $incidentId = 'SEC-' . $this->generateUuid();
                $this->sentinel->reportEvent([
                    'type'     => 'BOT_SPEED_SUBMISSION',
                    'severity' => 'HIGH',
                    'ruleId'   => 'SIG-BOT-002',
                    'sourceIp' => $clientIp,
                    'target'   => $path,
                    'details'  => "Form submitted suspiciously fast ({$validation['elapsed']}s < {$minSeconds}s threshold).",
                    'action'   => $mode === 'block' ? 'BLOCKED' : 'FLAGGED'
                ]);

                if ($mode === 'block') {
                    return $this->respondBlocked('Form submitted too fast. Automated robotic activity detected.', 'SIG-BOT-002', 'CWE-799', $incidentId);
                }
            }
        }

        // 4. Extract and Sanitize Inputs (Exclude sensitive fields)
        $inputs = $this->extractInspectableInputs($request);

        // 5. Inspect Payloads Across Normalization Pipeline
        $threat = $this->inspectInputs($inputs);

        if ($threat !== null) {
            $incidentId = 'SEC-' . $this->generateUuid();

            $this->sentinel->reportEvent([
                'type'     => 'INJECTION_THREAT',
                'severity' => $threat['severity'],
                'ruleId'   => $threat['id'],
                'sourceIp' => $clientIp,
                'target'   => $path,
                'details'  => "{$threat['name']} ({$threat['cwe']}) detected in parameter '{$threat['field']}'.",
                'action'   => $mode === 'block' ? 'BLOCKED' : 'FLAGGED'
            ]);

            if ($mode === 'block') {
                return $this->respondBlocked(
                    "Petición denegada por WebSentinel WAF: {$threat['name']}",
                    $threat['id'],
                    $threat['cwe'],
                    $incidentId
                );
            }
        }

        return $next($request);
    }

    /**
     * Checks if IP is whitelisted, supporting both exact IPs and CIDR masks.
     */
    public function isIpWhitelisted(string $ip, array $whitelist): bool
    {
        if (empty($whitelist)) {
            return false;
        }

        // Use Symfony IpUtils if available
        if (class_exists(IpUtils::class)) {
            return IpUtils::checkIp($ip, $whitelist);
        }

        // Standalone fallback CIDR evaluator
        foreach ($whitelist as $target) {
            if ($target === $ip) {
                return true;
            }
            if (strpos($target, '/') !== false && $this->cidrMatch($ip, $target)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Native PHP CIDR evaluator fallback.
     */
    protected function cidrMatch(string $ip, string $cidr): bool
    {
        [$subnet, $mask] = explode('/', $cidr, 2);
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) && filter_var($subnet, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            $ipLong = ip2long($ip);
            $subnetLong = ip2long($subnet);
            $maskLong = -1 << (32 - (int)$mask);
            return ($ipLong & $maskLong) === ($subnetLong & $maskLong);
        }
        return false;
    }

    /**
     * Extracts inputs from Query, Body, Headers and Path, stripping sensitive fields.
     */
    protected function extractInspectableInputs($request): array
    {
        $sensitiveKeys = function_exists('config')
            ? config('websentinel.sensitive_fields', [
                'password', 'password_confirmation', 'current_password', '_token', 'token', 'secret', 'api_key', 'authorization'
            ])
            : ['password', 'password_confirmation', 'current_password', '_token', 'token', 'secret', 'api_key', 'authorization'];

        $honeypotField = function_exists('config') ? config('websentinel.honeypot_field', 'websentinel_verification_token') : 'websentinel_verification_token';
        $timeField = function_exists('config') ? config('websentinel.honeypot_time_field', 'websentinel_ts') : 'websentinel_ts';

        $sensitiveMap = array_fill_keys(array_merge($sensitiveKeys, [$honeypotField, $timeField]), true);

        $inspectable = [];

        // 1. Path
        if (method_exists($request, 'path')) {
            $inspectable['__path__'] = $request->path();
        }

        // 2. Query Parameters
        $query = method_exists($request, 'query') ? $request->query() : [];
        if (is_array($query)) {
            $this->flattenAndFilter($query, $inspectable, 'query', $sensitiveMap);
        }

        // 3. Body Parameters (JSON / Form Data)
        $body = method_exists($request, 'all') ? $request->all() : (method_exists($request, 'input') ? $request->input() : []);
        if (is_array($body)) {
            $this->flattenAndFilter($body, $inspectable, 'body', $sensitiveMap);
        }

        // 4. Critical Headers (User-Agent, Referer)
        if (method_exists($request, 'header')) {
            $ua = $request->header('User-Agent');
            if (!empty($ua) && is_string($ua)) {
                $inspectable['header:user-agent'] = $ua;
            }
            $ref = $request->header('Referer');
            if (!empty($ref) && is_string($ref)) {
                $inspectable['header:referer'] = $ref;
            }
        }

        return $inspectable;
    }

    /**
     * Flattens nested arrays while omitting sensitive parameters.
     */
    protected function flattenAndFilter(array $data, array &$target, string $prefix, array $sensitiveMap): void
    {
        foreach ($data as $key => $value) {
            $lowerKey = strtolower((string)$key);
            if (isset($sensitiveMap[$lowerKey])) {
                continue; // Strictly omit sensitive data
            }

            $currentKey = "{$prefix}.{$key}";

            if (is_array($value)) {
                $this->flattenAndFilter($value, $target, $currentKey, $sensitiveMap);
            } elseif (is_scalar($value) || is_null($value)) {
                $target[$currentKey] = (string)$value;
            }
        }
    }

    /**
     * Inspects flattened inputs against signatures using both raw and normalized values.
     */
    public function inspectInputs(array $inputs): ?array
    {
        foreach ($inputs as $fieldName => $value) {
            if (!is_string($value) || empty($value)) {
                continue;
            }

            // Normalization pipeline
            $normalizedResult = Normalizer::normalize($value);
            $original = $normalizedResult['original'];
            $normalized = $normalizedResult['normalized'];

            foreach ($this->signatures as $sig) {
                $regex = $sig['regex'];
                if (@preg_match($regex, $original) || ($normalized !== $original && @preg_match($regex, $normalized))) {
                    return [
                        'id'       => $sig['id'],
                        'name'     => $sig['name'],
                        'category' => $sig['category'] ?? 'generic',
                        'severity' => $sig['severity'] ?? 'HIGH',
                        'cwe'      => $sig['cwe'] ?? 'CWE-00',
                        'score'    => $sig['score'] ?? 5,
                        'field'    => $fieldName,
                        'value'    => mb_substr($original, 0, 64)
                    ];
                }
            }
        }

        return null;
    }

    /**
     * Standard 403 Forbidden Response.
     */
    protected function respondBlocked(string $message, string $ruleId, string $cwe, string $incidentId)
    {
        $payload = [
            'success'    => false,
            'error'      => 'Forbidden by WebSentinel WAF',
            'message'    => $message,
            'rule'       => $ruleId,
            'cwe'        => $cwe,
            'incident'   => $incidentId,
            'timestamp'  => date('c')
        ];

        if (function_exists('response')) {
            return response()->json($payload, 403);
        }

        // Fallback for tests/plain environment
        return [
            'status'  => 403,
            'headers' => ['Content-Type' => 'application/json'],
            'body'    => json_encode($payload)
        ];
    }

    /**
     * Generates a pseudo-UUID v4.
     */
    protected function generateUuid(): string
    {
        $data = random_bytes(16);
        $data[6] = chr((ord($data[6]) & 0x0f) | 0x40);
        $data[8] = chr((ord($data[8]) & 0x3f) | 0x80);
        return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data), 4));
    }

    /**
     * Loads centralized signatures catalogue with robust built-in fallbacks.
     */
    protected function loadSignatures(): void
    {
        $customPath = function_exists('config') ? config('websentinel.signatures_path') : null;
        $defaultRepoPath = __DIR__ . '/../../../../rules/signatures.json';

        $candidatePath = $customPath && file_exists($customPath)
            ? $customPath
            : (file_exists($defaultRepoPath) ? $defaultRepoPath : null);

        if ($candidatePath !== null) {
            $json = @file_get_contents($candidatePath);
            if ($json !== false) {
                $decoded = json_decode($json, true);
                if (is_array($decoded) && count($decoded) > 0) {
                    $this->signatures = array_map(function ($sig) {
                        return [
                            'id'       => $sig['id'],
                            'name'     => $sig['name'],
                            'category' => $sig['category'] ?? 'generic',
                            'regex'    => '/' . str_replace('/', '\/', $sig['regex']) . '/i',
                            'severity' => $sig['severity'] ?? 'HIGH',
                            'cwe'      => $sig['cwe'] ?? 'CWE-00',
                            'score'    => $sig['score'] ?? 5,
                        ];
                    }, $decoded);
                    return;
                }
            }
        }

        // Built-in resilient fallback signatures (identical to rules/signatures.json)
        $this->signatures = [
            [
                'id'       => 'SIG-SQLI-001',
                'name'     => 'SQL Injection: Tautology / Boolean Bypass',
                'category' => 'sqli',
                'regex'    => '/(?:\'|"|\b)(?:OR|AND)\b\s*[^=<>!\s]+\s*(?:=|<>|!=|<|>|LIKE|ILIKE)\s*[^=<>!\s]+/i',
                'severity' => 'CRITICAL',
                'cwe'      => 'CWE-89',
                'score'    => 5
            ],
            [
                'id'       => 'SIG-SQLI-002',
                'name'     => 'SQL Injection: UNION-Based Exfiltration',
                'category' => 'sqli',
                'regex'    => '/\bUNION\b(?:\s+ALL)?\s+\bSELECT\b/i',
                'severity' => 'CRITICAL',
                'cwe'      => 'CWE-89',
                'score'    => 5
            ],
            [
                'id'       => 'SIG-SQLI-003',
                'name'     => 'SQL Injection: Comment / Stacked Query Termination',
                'category' => 'sqli',
                'regex'    => '/(?:(?:\'|"|\b(?:SELECT|FROM|WHERE|INSERT|UPDATE|DELETE|HAVING|ORDER\s+BY|GROUP\s+BY|UNION))\s*[^;]*?--|;\s*(?:DROP|ALTER|INSERT|UPDATE|DELETE|EXEC(?:UTE)?|SHUTDOWN)\b|--\s*$)/i',
                'severity' => 'CRITICAL',
                'cwe'      => 'CWE-89',
                'score'    => 5
            ],
            [
                'id'       => 'SIG-SQLI-004',
                'name'     => 'SQL Injection: Time Delay & Benchmark Functions',
                'category' => 'sqli',
                'regex'    => '/\b(?:SLEEP|BENCHMARK|WAITFOR\s+DELAY|PG_SLEEP)\s*\(/i',
                'severity' => 'CRITICAL',
                'cwe'      => 'CWE-89',
                'score'    => 5
            ],
            [
                'id'       => 'SIG-SQLI-005',
                'name'     => 'SQL Injection: System Metadata & Fingerprinting',
                'category' => 'sqli',
                'regex'    => '/(?:@@version|\bversion\s*\(\s*\)|\buser\s*\(\s*\)|\bcurrent_user\b|\bschema\s*\(\s*\))/i',
                'severity' => 'HIGH',
                'cwe'      => 'CWE-89',
                'score'    => 4
            ],
            [
                'id'       => 'SIG-XSS-001',
                'name'     => 'Cross-Site Scripting: Script Tag Injection',
                'category' => 'xss',
                'regex'    => '/<script\b[^>]*>[\s\S]*?(?:<\/script>|$)/i',
                'severity' => 'HIGH',
                'cwe'      => 'CWE-79',
                'score'    => 5
            ],
            [
                'id'       => 'SIG-XSS-002',
                'name'     => 'Cross-Site Scripting: Inline Event Handler',
                'category' => 'xss',
                'regex'    => '/\bon[a-z]{3,20}\s*=/i',
                'severity' => 'CRITICAL',
                'cwe'      => 'CWE-79',
                'score'    => 5
            ],
            [
                'id'       => 'SIG-XSS-003',
                'name'     => 'Cross-Site Scripting: JavaScript / Data URI Scheme',
                'category' => 'xss',
                'regex'    => '/(?:javascript\s*:|data\s*:\s*text\/html)/i',
                'severity' => 'HIGH',
                'cwe'      => 'CWE-79',
                'score'    => 4
            ],
            [
                'id'       => 'SIG-PATH-001',
                'name'     => 'Path Traversal: Directory Climb Sequence',
                'category' => 'path_traversal',
                'regex'    => '/(?:\.\.[\/\\\\]|%2e%2e[\/\\\\])/i',
                'severity' => 'HIGH',
                'cwe'      => 'CWE-22',
                'score'    => 4
            ],
            [
                'id'       => 'SIG-PATH-002',
                'name'     => 'LFI: Sensitive Configuration File Target',
                'category' => 'path_traversal',
                'regex'    => '/(?:(?:^|[\/\\\\])(?:etc\/passwd|win\.ini|boot\.ini|\.env(?:\.[a-z0-9_-]+)?|\.git(?:[\/\\\\].*)?)(?:$|[\s\/?#]))/i',
                'severity' => 'CRITICAL',
                'cwe'      => 'CWE-22',
                'score'    => 5
            ],
            [
                'id'       => 'SIG-CMD-001',
                'name'     => 'Command Injection: Pipeline & Chained Shell Execution',
                'category' => 'cmd_injection',
                'regex'    => '/(?:(?:;|\|\||\||&)\s*(?:cat\s+|whoami\b|id\b|uname\b|dir\b|ls\b|netstat\b|curl\b|wget\b|bash\b|sh\b|powershell\b|cmd(?:\.exe)?\b)|\b(?:cat|whoami|id|uname|ls)\b\s*\||`[^`]+`|\$\([^\)]+\))/i',
                'severity' => 'CRITICAL',
                'cwe'      => 'CWE-78',
                'score'    => 5
            ]
        ];
    }
}
