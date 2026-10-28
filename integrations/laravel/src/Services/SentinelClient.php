<?php

namespace WebSentinel\Services;

class SentinelClient
{
    protected string $daemonUrl;

    public function __construct()
    {
        $this->daemonUrl = rtrim(config('websentinel.daemon_url', 'http://127.0.0.1:4000'), '/');
    }

    /**
     * Report threat telemetry to WebSentinel-CS daemon.
     */
    public function reportThreat(array $payload): void
    {
        try {
            $ch = curl_init("{$this->daemonUrl}/api/analyze-request");
            $postData = json_encode([
                'input'          => $payload['details'] ?? '',
                'honeypot'       => '',
                'clientIp'       => $payload['ip'] ?? '127.0.0.1',
                'targetEndpoint' => $payload['target'] ?? '/api'
            ]);

            curl_setopt($ch, CURLOPT_POSTFIELDS, $postData);
            curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_TIMEOUT_MS, 300); // Non-blocking sub-second timeout
            curl_exec($ch);
            curl_close($ch);
        } catch (\Throwable $e) {
            // Out-of-band fail-safe: never crash application traffic if daemon is unreachable
            error_log('[WebSentinel-CS Client] Failed to emit telemetry: ' . $e->getMessage());
        }
    }
}
