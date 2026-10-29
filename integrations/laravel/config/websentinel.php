<?php

return [
    /*
    |--------------------------------------------------------------------------
    | WebSentinel Daemon Endpoint & API Authentication
    |--------------------------------------------------------------------------
    | Base URL of the standalone WebSentinel-CS node daemon and API Key
    | configured with 'ingest' scope for cryptographically verified telemetry.
    */
    'daemon_url' => env('WEBSENTINEL_DAEMON_URL', 'http://127.0.0.1:4000'),
    'api_key'    => env('WEBSENTINEL_API_KEY', ''),

    /*
    |--------------------------------------------------------------------------
    | Firewall Mode of Operation
    |--------------------------------------------------------------------------
    | 'block'   : Denies threat vectors immediately with 403 JSON (incident code SEC-...).
    | 'monitor' : Emits out-of-band telemetry to Sentinel without blocking traffic.
    */
    'mode' => env('WEBSENTINEL_MODE', 'block'),

    /*
    |--------------------------------------------------------------------------
    | Zero-Latency Asynchronous Telemetry
    |--------------------------------------------------------------------------
    | If true, telemetry is dispatched inside the app()->terminating() hook
    | after the HTTP response has been flushed to the client's browser.
    | Fail-open timeout is capped at 200ms.
    */
    'async_telemetry' => env('WEBSENTINEL_ASYNC', true),
    'timeout_ms'      => (int) env('WEBSENTINEL_TIMEOUT_MS', 200),

    /*
    |--------------------------------------------------------------------------
    | Automated Honeypot Bot Trap
    |--------------------------------------------------------------------------
    | Form field names and minimum submission latency in seconds.
    */
    'honeypot_field'            => env('WEBSENTINEL_HONEYPOT', 'websentinel_verification_token'),
    'honeypot_time_field'       => env('WEBSENTINEL_HONEYPOT_TIME', 'websentinel_ts'),
    'honeypot_min_time_seconds' => (int) env('WEBSENTINEL_HONEYPOT_MIN_TIME', 1),
    'honeypot_secret'           => env('WEBSENTINEL_SECRET', env('APP_KEY', 'base64:websentinel-default-secret-key-32b')),

    /*
    |--------------------------------------------------------------------------
    | Excluded Routes
    |--------------------------------------------------------------------------
    | URI patterns that completely bypass the WebSentinel inspection engine.
    */
    'excluded_routes' => [
        'telescope*',
        'horizon*',
        'sanctum/csrf-cookie',
        '_debugbar*'
    ],

    /*
    |--------------------------------------------------------------------------
    | IP & CIDR Whitelist
    |--------------------------------------------------------------------------
    | Subnets and specific IPs that bypass all WAF inspection checks.
    | Supports exact IPs ('127.0.0.1') and CIDR blocks ('192.168.1.0/24').
    */
    'ip_whitelist' => [
        '127.0.0.1',
        '::1'
    ],

    /*
    |--------------------------------------------------------------------------
    | Sensitive Fields (Data Privacy & Secret Masking)
    |--------------------------------------------------------------------------
    | Fields automatically stripped from inspection and telemetry payloads.
    */
    'sensitive_fields' => [
        'password',
        'password_confirmation',
        'current_password',
        'new_password',
        '_token',
        'token',
        'secret',
        'api_key',
        'credit_card',
        'card_number',
        'cvv',
        'cvc',
        'authorization'
    ],

    /*
    |--------------------------------------------------------------------------
    | Real User Session & Activity Auditing
    |--------------------------------------------------------------------------
    | Automatically feeds the WebSentinel SOC "Auditoría de Sesiones" tab.
    */
    'track_activities' => env('WEBSENTINEL_TRACK_ACTIVITIES', true),

    /*
    |--------------------------------------------------------------------------
    | Signatures File Location (Optional Local Path)
    |--------------------------------------------------------------------------
    */
    'signatures_path' => env('WEBSENTINEL_SIGNATURES_PATH', null),
];
