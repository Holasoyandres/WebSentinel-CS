<?php

namespace WebSentinel\Http\Middleware;

use Closure;
use WebSentinel\Services\SentinelClient;

class WebSentinelTrackActivity
{
    protected SentinelClient $sentinel;

    public function __construct(SentinelClient $sentinel)
    {
        $this->sentinel = $sentinel;
    }

    /**
     * Track authenticated user in-session activity and stream to WebSentinel SOC.
     *
     * @param mixed $request
     * @param \Closure $next
     * @return mixed
     */
    public function handle($request, Closure $next)
    {
        $response = $next($request);

        try {
            if (!function_exists('config') || !config('websentinel.track_activities', true)) {
                return $response;
            }

            // Only track if user is authenticated and session is active
            if (function_exists('auth') && auth()->check() && function_exists('session') && session()->isStarted()) {
                $sessionId = session()->getId();
                $method = method_exists($request, 'method') ? $request->method() : 'GET';
                $path = method_exists($request, 'path') ? $request->path() : '/';

                $route = method_exists($request, 'route') ? $request->route() : null;
                $actionName = $route && method_exists($route, 'getName') && $route->getName()
                    ? $route->getName()
                    : ($route && method_exists($route, 'getActionName') ? $route->getActionName() : "{$method} /{$path}");

                $details = [
                    'ip'        => method_exists($request, 'ip') ? $request->ip() : '127.0.0.1',
                    'method'    => $method,
                    'status'    => method_exists($response, 'getStatusCode') ? $response->getStatusCode() : 200,
                    'user_id'   => auth()->id(),
                    'timestamp' => date('c')
                ];

                $this->sentinel->reportSessionActivity(
                    $sessionId,
                    (string)$actionName,
                    (string)$path,
                    $details
                );
            }
        } catch (\Throwable $e) {
            // Out-of-band: never interfere with normal response delivery
            error_log('[WebSentinelTrackActivity] ' . $e->getMessage());
        }

        return $response;
    }
}
