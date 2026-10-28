<?php

namespace WebSentinel\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;
use WebSentinel\Services\SentinelClient;

class WebSentinelFirewall
{
    protected SentinelClient $sentinel;

    public function __construct(SentinelClient $sentinel)
    {
        $this->sentinel = $sentinel;
    }

    /**
     * Intercept incoming HTTP request and analyze for threats.
     */
    public function handle(Request $request, Closure $next): Response
    {
        // 1. Check IP Whitelist
        $clientIp = $request->ip();
        if (in_array($clientIp, config('websentinel.ip_whitelist', []))) {
            return $next($request);
        }

        // 2. Check Route Exclusion
        foreach (config('websentinel.excluded_routes', []) as $excluded) {
            if ($request->is($excluded)) {
                return $next($request);
            }
        }

        // 3. Inspect Honeypot
        $honeypotField = config('websentinel.honeypot_field', 'websentinel_verification_token');
        $honeypotValue = $request->input($honeypotField, '');
        if (!empty($honeypotValue)) {
            $this->sentinel->reportThreat([
                'type'     => 'BOT_ANOMALY',
                'severity' => 'HIGH',
                'rule_id'  => 'SIG-BOT-001',
                'ip'       => $clientIp,
                'target'   => $request->path(),
                'details'  => 'Automated crawler filled hidden honeypot token.',
                'action'   => 'BLOCKED'
            ]);

            if (config('websentinel.mode') === 'block') {
                return response()->json([
                    'error'   => 'Security Verification Failed',
                    'message' => 'Automated bot activity detected by WebSentinel Firewall.'
                ], 403);
            }
        }

        // 4. Inspect Query & Body Parameters for Injection
        $payloadString = json_encode($request->except([$honeypotField, '_token', 'password']));
        $threat = $this->inspectPatterns($payloadString);

        if ($threat) {
            $this->sentinel->reportThreat([
                'type'     => 'INJECTION_THREAT',
                'severity' => $threat['severity'],
                'rule_id'  => $threat['rule_id'],
                'ip'       => $clientIp,
                'target'   => $request->path(),
                'details'  => "{$threat['name']} ({$threat['cwe']}) detected in request payload.",
                'action'   => config('websentinel.mode') === 'block' ? 'BLOCKED' : 'FLAGGED'
            ]);

            if (config('websentinel.mode') === 'block') {
                return response()->json([
                    'error'     => 'Forbidden by WebSentinel WAF',
                    'rule'      => $threat['rule_id'],
                    'cwe'       => $threat['cwe'],
                    'incident'  => 'SEC-' . strtoupper(substr(md5(uniqid()), 0, 8))
                ], 403);
            }
        }

        return $next($request);
    }

    /**
     * Inspect string against OWASP heuristic patterns.
     */
    protected function inspectPatterns(string $input): ?array
    {
        $patterns = [
            [
                'rule_id'  => 'SIG-SQLI-001',
                'name'     => 'SQL Injection: Tautology',
                'regex'    => "/('|\b)(OR|AND)\b.+(=|<|>).+/i",
                'severity' => 'CRITICAL',
                'cwe'      => 'CWE-89'
            ],
            [
                'rule_id'  => 'SIG-SQLI-002',
                'name'     => 'SQL Injection: UNION-Based',
                'regex'    => "/\bUNION\b\s+(\bALL\b\s+)?\bSELECT\b/i",
                'severity' => 'CRITICAL',
                'cwe'      => 'CWE-89'
            ],
            [
                'rule_id'  => 'SIG-XSS-001',
                'name'     => 'Cross-Site Scripting: Tag Injection',
                'regex'    => "/<script\b[^>]*>([\s\S]*?)<\/script>/i",
                'severity' => 'HIGH',
                'cwe'      => 'CWE-79'
            ],
            [
                'rule_id'  => 'SIG-PATH-001',
                'name'     => 'Path Traversal: Climb Sequence',
                'regex'    => "/(\.\.\/|\.\.\\)/i",
                'severity' => 'HIGH',
                'cwe'      => 'CWE-22'
            ]
        ];

        foreach ($patterns as $p) {
            if (preg_match($p['regex'], $input)) {
                return $p;
            }
        }

        return null;
    }
}
