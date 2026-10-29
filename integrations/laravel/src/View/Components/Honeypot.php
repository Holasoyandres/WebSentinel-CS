<?php

namespace WebSentinel\View\Components;

class Honeypot
{
    /**
     * Generate signed timestamp token for speed submission defense.
     */
    public static function generateTimestampToken(?string $secret = null): string
    {
        $time = time();
        $key = $secret ?? (function_exists('config') ? config('websentinel.honeypot_secret', 'websentinel-secret') : 'websentinel-secret');
        $hash = hash_hmac('sha256', (string)$time, $key);
        return base64_encode("{$time}:{$hash}");
    }

    /**
     * Validate timestamp token against minimum elapsed time threshold.
     *
     * @return array{valid: bool, elapsed: int, isBot: bool}
     */
    public static function validateTimestampToken(?string $token, int $minSeconds = 1, ?string $secret = null): array
    {
        if (empty($token)) {
            return ['valid' => false, 'elapsed' => 0, 'isBot' => true];
        }

        $decoded = base64_decode($token, true);
        if ($decoded === false || strpos($decoded, ':') === false) {
            return ['valid' => false, 'elapsed' => 0, 'isBot' => true];
        }

        [$timestampStr, $hash] = explode(':', $decoded, 2);
        $timestamp = (int)$timestampStr;
        $key = $secret ?? (function_exists('config') ? config('websentinel.honeypot_secret', 'websentinel-secret') : 'websentinel-secret');
        $expectedHash = hash_hmac('sha256', (string)$timestamp, $key);

        if (!hash_equals($expectedHash, $hash)) {
            return ['valid' => false, 'elapsed' => 0, 'isBot' => true];
        }

        $elapsed = time() - $timestamp;

        // If submitted faster than threshold or from the future (> 86400s old or negative)
        if ($elapsed < $minSeconds || $elapsed > 86400) {
            return ['valid' => true, 'elapsed' => $elapsed, 'isBot' => true];
        }

        return ['valid' => true, 'elapsed' => $elapsed, 'isBot' => false];
    }

    /**
     * Renders standard invisible honeypot HTML markup.
     */
    public static function renderHtml(?string $fieldName = null, ?string $timeFieldName = null, ?string $secret = null): string
    {
        $field = $fieldName ?? (function_exists('config') ? config('websentinel.honeypot_field', 'websentinel_verification_token') : 'websentinel_verification_token');
        $timeField = $timeFieldName ?? (function_exists('config') ? config('websentinel.honeypot_time_field', 'websentinel_ts') : 'websentinel_ts');
        $token = self::generateTimestampToken($secret);

        return <<<HTML
<div class="websentinel-verification-wrap" style="position: absolute !important; left: -9999px !important; top: -9999px !important; opacity: 0 !important; pointer-events: none !important; width: 0 !important; height: 0 !important; overflow: hidden !important;" aria-hidden="true" tabindex="-1">
    <label for="{$field}">Leave this field empty</label>
    <input type="text" name="{$field}" id="{$field}" value="" tabindex="-1" autocomplete="off">
    <input type="hidden" name="{$timeField}" value="{$token}">
</div>
HTML;
    }
}
