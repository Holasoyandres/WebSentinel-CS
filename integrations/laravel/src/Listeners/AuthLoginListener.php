<?php

namespace WebSentinel\Listeners;

use WebSentinel\Services\SentinelClient;

class AuthLoginListener
{
    protected SentinelClient $sentinel;

    public function __construct(SentinelClient $sentinel)
    {
        $this->sentinel = $sentinel;
    }

    /**
     * Handle user login event.
     *
     * @param object $event Usually Illuminate\Auth\Events\Login
     */
    public function handle(object $event): void
    {
        try {
            $user = $event->user ?? null;
            $userId = $user ? (string)($user->getAuthIdentifier() ?? $user->id ?? 'unknown') : 'unknown';
            $identifier = $user->email ?? $user->username ?? $userId;

            $request = function_exists('request') ? request() : null;
            $ip = $request ? $request->ip() : '127.0.0.1';
            $userAgent = $request ? ($request->userAgent() ?? 'Unknown') : 'Unknown';

            $sessionId = function_exists('session') && session()->isStarted()
                ? session()->getId()
                : 'sess_' . bin2hex(random_bytes(16));

            // 1. Feed persistent brute-force sliding window
            $this->sentinel->reportLogin($ip, $identifier, true);

            // 2. Feed persistent SOC Session Audit
            $this->sentinel->reportSessionLogin($sessionId, $userId, $ip, $userAgent);
        } catch (\Throwable $e) {
            error_log('[WebSentinel AuthLoginListener] ' . $e->getMessage());
        }
    }
}
