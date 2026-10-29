<?php

namespace WebSentinel\Services;

class SentinelClient
{
    protected string $daemonUrl;
    protected string $apiKey;
    protected int $timeoutMs;
    protected bool $async;

    public function __construct(?string $daemonUrl = null, ?string $apiKey = null, ?int $timeoutMs = null, ?bool $async = null)
    {
        $this->daemonUrl = rtrim($daemonUrl ?? (function_exists('config') ? config('websentinel.daemon_url', 'http://127.0.0.1:4000') : 'http://127.0.0.1:4000'), '/');
        $this->apiKey    = $apiKey ?? (function_exists('config') ? (config('websentinel.api_key') ?? '') : '');
        $this->timeoutMs = $timeoutMs ?? (function_exists('config') ? (int)config('websentinel.timeout_ms', 200) : 200);
        $this->async     = $async ?? (function_exists('config') ? (bool)config('websentinel.async_telemetry', true) : true);
    }

    /**
     * Report structured security event to dedicated POST /api/v1/events endpoint.
     */
    public function reportEvent(array $event): void
    {
        $payload = [
            'type'        => $event['type'] ?? 'SECURITY_ALERT',
            'severity'    => $event['severity'] ?? 'HIGH',
            'ruleId'      => $event['ruleId'] ?? $event['rule_id'] ?? 'RULE-LARAVEL-01',
            'sourceIp'    => $event['sourceIp'] ?? $event['ip'] ?? '127.0.0.1',
            'target'      => $event['target'] ?? '/',
            'details'     => $event['details'] ?? 'Laravel Security Telemetry',
            'action'      => $event['action'] ?? 'BLOCKED',
            'isSimulated' => false
        ];

        $this->dispatch('/api/v1/events', $payload);
    }

    /**
     * Report user authentication attempt (success or failure) to /api/record-login.
     * Feeds Sentinel persistent brute-force sliding window and IP reputation.
     */
    public function reportLogin(string $ip, string $identifier, bool $success): void
    {
        $payload = [
            'clientIp'   => $ip,
            'identifier' => $identifier,
            'success'    => $success
        ];

        $this->dispatch('/api/record-login', $payload);
    }

    /**
     * Report user session start to /api/sessions/login.
     * Directly populates WebSentinel SOC "Auditoría de Sesiones" dashboard.
     */
    public function reportSessionLogin(string $sessionId, string $userId, string $ip, string $userAgent): void
    {
        $payload = [
            'sessionId' => $sessionId,
            'userId'    => $userId,
            'ip'        => $ip,
            'userAgent' => $userAgent
        ];

        $this->dispatch('/api/sessions/login', $payload);
    }

    /**
     * Report user authenticated in-session activity to /api/sessions/activity.
     */
    public function reportSessionActivity(string $sessionId, string $action, ?string $target = null, ?array $details = null): void
    {
        $payload = [
            'sessionId' => $sessionId,
            'action'    => $action,
            'target'    => $target ?? '/',
            'details'   => $details ? json_encode($details) : null
        ];

        $this->dispatch('/api/sessions/activity', $payload);
    }

    /**
     * Report user session termination to /api/sessions/logout.
     */
    public function reportSessionLogout(string $sessionId): void
    {
        $payload = [
            'sessionId' => $sessionId
        ];

        $this->dispatch('/api/sessions/logout', $payload);
    }

    /**
     * Zero-latency dispatch mechanism: leverages Laravel terminating callback
     * when available, or executes fail-open curl request.
     */
    protected function dispatch(string $endpoint, array $payload): void
    {
        if ($this->async && function_exists('app')) {
            try {
                $app = app();
                if (is_object($app) && method_exists($app, 'terminating')) {
                    $app->terminating(function () use ($endpoint, $payload) {
                        $this->sendHttp($endpoint, $payload);
                    });
                    return;
                }
            } catch (\Throwable $e) {
                // If container or terminating hook is unavailable, proceed synchronously
            }
        }

        $this->sendHttp($endpoint, $payload);
    }

    /**
     * Executes fail-open HTTP POST request with sub-second timeout.
     * Guaranteed never to crash the host application.
     */
    public function sendHttp(string $endpoint, array $payload): bool
    {
        try {
            $url = "{$this->daemonUrl}{$endpoint}";
            $json = json_encode($payload);

            $headers = [
                'Content-Type: application/json',
                'Content-Length: ' . strlen($json)
            ];

            if (!empty($this->apiKey)) {
                $headers[] = "X-Sentinel-Key: {$this->apiKey}";
            }

            $ch = curl_init($url);
            curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'POST');
            curl_setopt($ch, CURLOPT_POSTFIELDS, $json);
            curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_TIMEOUT_MS, $this->timeoutMs);
            curl_setopt($ch, CURLOPT_CONNECTTIMEOUT_MS, $this->timeoutMs);
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
            curl_setopt($ch, CURLOPT_NOSIGNAL, 1);

            $response = curl_exec($ch);
            $err = curl_error($ch);
            $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);

            if ($response === false) {
                error_log("[WebSentinel-CS Client] Out-of-band telemetry timeout/failed: {$err}");
                return false;
            }

            return $httpCode >= 200 && $httpCode < 300;
        } catch (\Throwable $e) {
            error_log('[WebSentinel-CS Client] Exception during telemetry dispatch: ' . $e->getMessage());
            return false;
        }
    }
}
