<?php

return [
    /*
    |--------------------------------------------------------------------------
    | WebSentinel Daemon Endpoint
    |--------------------------------------------------------------------------
    | URL of the standalone WebSentinel-CS daemon.
    */
    'daemon_url' => env('WEBSENTINEL_DAEMON_URL', 'http://127.0.0.1:4000'),

    /*
    |--------------------------------------------------------------------------
    | Firewall Mode
    |--------------------------------------------------------------------------
    | 'block'   : Drop malicious requests with 403 Forbidden.
    | 'monitor' : Log and report telemetry without blocking traffic.
    */
    'mode' => env('WEBSENTINEL_MODE', 'block'),

    /*
    |--------------------------------------------------------------------------
    | Honeypot Bot Field
    |--------------------------------------------------------------------------
    | Name of the hidden honeypot form input to trap automated bots.
    */
    'honeypot_field' => env('WEBSENTINEL_HONEYPOT', 'websentinel_verification_token'),

    /*
    |--------------------------------------------------------------------------
    | Excluded Routes
    |--------------------------------------------------------------------------
    | Routes that should bypass the security inspection engine.
    */
    'excluded_routes' => [
        'telescope*',
        'horizon*',
        'sanctum/csrf-cookie'
    ],

    /*
    |--------------------------------------------------------------------------
    | Whitelisted IP Addresses
    |--------------------------------------------------------------------------
    */
    'ip_whitelist' => [
        '127.0.0.1',
        '::1'
    ],

    /*
    |--------------------------------------------------------------------------
    | Threat Signatures
    |--------------------------------------------------------------------------
    */
    'signatures' => [
        'sqli'           => true,
        'xss'            => true,
        'path_traversal' => true,
        'honeypot'       => true,
    ],
];
