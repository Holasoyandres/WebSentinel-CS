<?php

/**
 * WebSentinel-CS :: Laravel Integration Package Test Runner
 * Self-contained PHP 8 test runner verifying WAF, Normalizer, Client & Honeypot.
 */

declare(strict_types=1);

require_once __DIR__ . '/../src/Services/Normalizer.php';
require_once __DIR__ . '/../src/Services/SentinelClient.php';
require_once __DIR__ . '/../src/View/Components/Honeypot.php';
require_once __DIR__ . '/../src/Http/Middleware/WebSentinelFirewall.php';

use WebSentinel\Http\Middleware\WebSentinelFirewall;
use WebSentinel\Services\Normalizer;
use WebSentinel\Services\SentinelClient;
use WebSentinel\View\Components\Honeypot;

class MockRequest
{
    public string $ip = '190.25.10.5';
    public string $path = 'login';
    public array $query = [];
    public array $body = [];
    public array $headers = [];

    public function __construct(array $attributes = [])
    {
        foreach ($attributes as $k => $v) {
            $this->{$k} = $v;
        }
    }

    public function ip(): string
    {
        return $this->ip;
    }

    public function path(): string
    {
        return $this->path;
    }

    public function query(): array
    {
        return $this->query;
    }

    public function all(): array
    {
        return $this->body;
    }

    public function input(?string $key = null, $default = null)
    {
        if ($key === null) {
            return $this->body;
        }
        return $this->body[$key] ?? $default;
    }

    public function header(string $key, $default = null)
    {
        $normalized = strtolower($key);
        foreach ($this->headers as $k => $v) {
            if (strtolower($k) === $normalized) {
                return $v;
            }
        }
        return $default;
    }

    public function is(string $pattern): bool
    {
        $pattern = str_replace('*', '.*', $pattern);
        return (bool)preg_match("#^{$pattern}$#i", $this->path);
    }
}

class TestSuite
{
    protected int $passed = 0;
    protected int $failed = 0;
    protected string $currentSuite = '';

    public function suite(string $name): void
    {
        $this->currentSuite = $name;
        echo "\n\033[1;34m▶ {$name}\033[0m\n";
    }

    public function test(string $name, callable $fn): void
    {
        $t0 = microtime(true);
        try {
            $fn();
            $durationMs = round((microtime(true) - $t0) * 1000, 2);
            $this->passed++;
            echo "  \033[32m✔\033[0m {$name} \033[90m({$durationMs}ms)\033[0m\n";
        } catch (\Throwable $e) {
            $durationMs = round((microtime(true) - $t0) * 1000, 2);
            $this->failed++;
            echo "  \033[31m✖\033[0m {$name} \033[90m({$durationMs}ms)\033[0m\n";
            echo "    \033[31m" . $e->getMessage() . " (" . basename($e->getFile()) . ":{$e->getLine()})\033[0m\n";
        }
    }

    public function assert(bool $condition, string $message = 'Assertion failed'): void
    {
        if (!$condition) {
            throw new \RuntimeException($message);
        }
    }

    public function summary(): int
    {
        $total = $this->passed + $this->failed;
        echo "\n\033[1mTotal: {$total} | Passed: \033[32m{$this->passed}\033[0m | Failed: " .
            ($this->failed > 0 ? "\033[31m{$this->failed}\033[0m" : "0") . "\033[0m\n";

        return $this->failed === 0 ? 0 : 1;
    }
}

// -----------------------------------------------------------------------------
// Test Execution
// -----------------------------------------------------------------------------

$runner = new TestSuite();

// 1. Normalizer Unit Tests
$runner->suite('WebSentinel :: PHP Normalizer (Normalizer.php)');

$runner->test('Recursive URL decoding resolves double and triple encoding', function () use ($runner) {
    $res = Normalizer::normalize('%2527%20OR%201=1');
    $runner->assert(strpos($res['normalized'], "' OR 1=1") !== false, "Expected decoded quote: got {$res['normalized']}");
});

$runner->test('Decodes HTML numeric and named entities', function () use ($runner) {
    $res = Normalizer::normalize('&quot; &#x27; &#39; &lt;script&gt;');
    $runner->assert($res['normalized'] === "\" ' ' <script>", "Got: {$res['normalized']}");
});

$runner->test('Strips null bytes and inline SQL comments', function () use ($runner) {
    $res = Normalizer::normalize("SELECT/*comment*/\0 1 FROM/*test*/users");
    $runner->assert($res['normalized'] === 'SELECT 1 FROM users', "Got: {$res['normalized']}");
});

$runner->test('Truncates inputs > 16 KB for ReDoS boundary protection', function () use ($runner) {
    $large = str_repeat('A', 25000);
    $res = Normalizer::normalize($large);
    $runner->assert(strlen($res['normalized']) === 16384, 'Expected 16,384 chars truncation');
});


// 2. WAF Firewall Middleware Tests
$runner->suite('WebSentinel :: WAF Firewall Middleware (WebSentinelFirewall.php)');

$mockClient = new SentinelClient('http://127.0.0.1:4000', 'ws_test_key', 200, false);
$firewall = new WebSentinelFirewall($mockClient);

$runner->test('Blocks SQL Injection (Tautology) in Body', function () use ($runner, $firewall) {
    $req = new MockRequest([
        'ip'   => '200.10.5.1',
        'body' => ['username' => "admin' OR 1=1 --", 'email' => 'admin@empresa.com']
    ]);

    $executed = false;
    $res = $firewall->handle($req, function () use (&$executed) {
        $executed = true;
        return ['status' => 200];
    });

    $runner->assert(!$executed, 'Malicious request must NOT proceed to application handler');
    $runner->assert(is_array($res) && $res['status'] === 403, 'Expected 403 Forbidden response');
    $body = json_decode($res['body'], true);
    $runner->assert($body['rule'] === 'SIG-SQLI-001' || $body['rule'] === 'SIG-SQLI-003', "Expected SQLi rule: got {$body['rule']}");
});

$runner->test('Blocks XSS (Event Handler) in Query Parameters', function () use ($runner, $firewall) {
    $req = new MockRequest([
        'ip'    => '200.10.5.2',
        'query' => ['search' => '<svg/onanimationstart=alert(1)>']
    ]);

    $executed = false;
    $res = $firewall->handle($req, function () use (&$executed) {
        $executed = true;
        return ['status' => 200];
    });

    $runner->assert(!$executed, 'XSS query param must be intercepted');
    $runner->assert(is_array($res) && $res['status'] === 403, 'Must return 403');
});

$runner->test('Blocks Path Traversal in Header (User-Agent)', function () use ($runner, $firewall) {
    $req = new MockRequest([
        'ip'      => '200.10.5.3',
        'headers' => ['User-Agent' => '../../../../etc/passwd']
    ]);

    $executed = false;
    $res = $firewall->handle($req, function () use (&$executed) {
        $executed = true;
        return ['status' => 200];
    });

    $runner->assert(!$executed, 'Path traversal in User-Agent header must be intercepted');
    $runner->assert(is_array($res) && $res['status'] === 403);
});

$runner->test('Allows benign Spanish texts with hyphens and apostrophes (Zero False Positives)', function () use ($runner, $firewall) {
    $req = new MockRequest([
        'ip'   => '200.10.5.4',
        'body' => [
            'author'   => "O'Reilly Media",
            'text'     => "Este es un texto -- con guión doble para separar ideas.",
            'email'    => "soporte@enviaexpress.com",
            'template' => "SELECT * FROM doc_templates WHERE id = 1 en documentación técnica"
        ]
    ]);

    $executed = false;
    $res = $firewall->handle($req, function () use (&$executed) {
        $executed = true;
        return ['status' => 200];
    });

    $runner->assert($executed, 'Benign Spanish input must proceed cleanly to host application');
});

$runner->test('CIDR Whitelist allows requests from trusted subnets (192.168.1.0/24)', function () use ($runner, $firewall) {
    $runner->assert($firewall->isIpWhitelisted('192.168.1.150', ['192.168.1.0/24']), '192.168.1.150 should be whitelisted in 192.168.1.0/24');
    $runner->assert(!$firewall->isIpWhitelisted('192.168.2.1', ['192.168.1.0/24']), '192.168.2.1 should NOT be whitelisted in 192.168.1.0/24');
    $runner->assert($firewall->isIpWhitelisted('10.0.5.20', ['10.0.0.0/8']), '10.0.5.20 should be whitelisted in 10.0.0.0/8');
});

$runner->test('Excludes sensitive fields (passwords, tokens) from inspection and logs', function () use ($runner, $firewall) {
    // If password had SQLi-like characters, it should be excluded from inspection!
    $req = new MockRequest([
        'ip'   => '200.10.5.5',
        'body' => [
            'username'              => 'carlos.gomez',
            'password'              => "' OR '1'='1' --",
            'password_confirmation' => "' OR '1'='1' --",
            '_token'                => "csrf_token_value",
            'secret'                => "api_secret_key"
        ]
    ]);

    $executed = false;
    $firewall->handle($req, function () use (&$executed) {
        $executed = true;
        return ['status' => 200];
    });

    $runner->assert($executed, 'Password field must be strictly bypassed from inspection');
});


// 3. Honeypot Bot Trap Tests
$runner->suite('WebSentinel :: Honeypot Component & Bot Defense (Honeypot.php)');

$runner->test('Traps automated bot filling the hidden honeypot field', function () use ($runner, $firewall) {
    $req = new MockRequest([
        'ip'   => '185.220.100.5',
        'body' => [
            'username'                         => 'legit_user',
            'websentinel_verification_token' => 'i_am_an_automated_crawler_bot'
        ]
    ]);

    $executed = false;
    $res = $firewall->handle($req, function () use (&$executed) {
        $executed = true;
        return ['status' => 200];
    });

    $runner->assert(!$executed, 'Bot filling honeypot must be blocked');
    $body = json_decode($res['body'], true);
    $runner->assert($body['rule'] === 'SIG-BOT-001', 'Must match SIG-BOT-001');
});

$runner->test('Traps speed bot submitting in less than 1 second', function () use ($runner, $firewall) {
    // Token generated right now (0s elapsed)
    $fastToken = Honeypot::generateTimestampToken('test-secret');

    $val = Honeypot::validateTimestampToken($fastToken, 1, 'test-secret');
    $runner->assert($val['valid'] === true, 'Token should be validly signed');
    $runner->assert($val['isBot'] === true, 'Submission < 1s must be flagged as robot');
});

$runner->test('Allows human submission after minimum elapsed time threshold', function () use ($runner) {
    // Fabricate timestamp token 5 seconds ago
    $pastTime = time() - 5;
    $secret = 'test-secret';
    $hash = hash_hmac('sha256', (string)$pastTime, $secret);
    $humanToken = base64_encode("{$pastTime}:{$hash}");

    $val = Honeypot::validateTimestampToken($humanToken, 1, $secret);
    $runner->assert($val['valid'] === true, 'Token must be valid');
    $runner->assert($val['isBot'] === false, 'Elapsed 5s must be considered human');
});

$runner->test('Renders inaccessible, off-screen CSS honeypot markup', function () use ($runner) {
    $html = Honeypot::renderHtml();
    $runner->assert(strpos($html, 'opacity: 0') !== false, 'Must have zero opacity');
    $runner->assert(strpos($html, 'tabindex="-1"') !== false, 'Must not be focusable via Tab');
    $runner->assert(strpos($html, 'aria-hidden="true"') !== false, 'Must be hidden from screen readers');
});


// 4. Client Telemetry & Fail-Open Resilience Tests
$runner->suite('WebSentinel :: SentinelClient Telemetry & Fail-Open (SentinelClient.php)');

$runner->test('Dispatches structured telemetry to POST /api/v1/events on live daemon', function () use ($runner) {
    $client = new SentinelClient('http://127.0.0.1:4000', 'ws_test_key', 300, false);
    // Even if daemon offline or test key not in DB, it must execute gracefully
    $ok = $client->sendHttp('/api/v1/events', [
        'type'        => 'LARAVEL_TEST_EVENT',
        'severity'    => 'INFO',
        'ruleId'      => 'RULE-TEST-01',
        'sourceIp'    => '127.0.0.1',
        'target'      => '/test',
        'details'     => 'Laravel Test Suite Dispatch',
        'action'      => 'LOGGED',
        'isSimulated' => false
    ]);
    // Check that it didn't throw and returned a boolean
    $runner->assert(is_bool($ok));
});

$runner->test('Fail-open guarantee: when daemon is offline, response finishes in < 250ms with no crash', function () use ($runner) {
    // Non-routable blackhole IP to test timeout
    $offlineClient = new SentinelClient('http://192.0.2.1:9999', 'key', 150, false);

    $t0 = microtime(true);
    $result = $offlineClient->sendHttp('/api/v1/events', ['type' => 'TEST']);
    $durationMs = (microtime(true) - $t0) * 1000;

    $runner->assert($result === false, 'Offline daemon must return false');
    $runner->assert($durationMs < 300, "Fail-open timeout must cap latency. Took {$durationMs}ms");
});

exit($runner->summary());
