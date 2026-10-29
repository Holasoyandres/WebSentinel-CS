<?php

namespace WebSentinel\Listeners;

use WebSentinel\Services\SentinelClient;

class AuthFailedListener
{
    protected SentinelClient $sentinel;

    public function __construct(SentinelClient $sentinel)
    {
        $this->sentinel = $sentinel;
    }

    /**
     * Handle user authentication failure event.
     *
     * @param object $event Usually Illuminate\Auth\Events\Failed
     */
    public function handle(object $event): void
    {
        try {
            $credentials = $event->credentials ?? [];
            $identifier = $credentials['email'] ?? $credentials['username'] ?? $credentials['login'] ?? 'anonymous';

            $request = function_exists('request') ? request() : null;
            $ip = $request ? $request->ip() : '127.0.0.1';

            // Feed persistent brute-force sliding window & IP reputation
            $this->sentinel->reportLogin($ip, (string)$identifier, false);
        } catch (\Throwable $e) {
            error_log('[WebSentinel AuthFailedListener] ' . $e->getMessage());
        }
    }
}
