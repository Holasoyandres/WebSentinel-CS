<?php

namespace WebSentinel\Listeners;

use WebSentinel\Services\SentinelClient;

class AuthLogoutListener
{
    protected SentinelClient $sentinel;

    public function __construct(SentinelClient $sentinel)
    {
        $this->sentinel = $sentinel;
    }

    /**
     * Handle user logout event.
     *
     * @param object $event Usually Illuminate\Auth\Events\Logout
     */
    public function handle(object $event): void
    {
        try {
            $sessionId = function_exists('session') && session()->isStarted()
                ? session()->getId()
                : null;

            if ($sessionId) {
                $this->sentinel->reportSessionLogout($sessionId);
            }
        } catch (\Throwable $e) {
            error_log('[WebSentinel AuthLogoutListener] ' . $e->getMessage());
        }
    }
}
