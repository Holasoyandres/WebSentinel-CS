<?php

namespace WebSentinel\Services;

class Normalizer
{
    public const MAX_INSPECTION_LENGTH = 16384; // 16 KB ReDoS boundary

    /**
     * Recursively decodes URL encoding up to $maxPasses times.
     */
    public static function recursiveUrlDecode(string $input, int $maxPasses = 3): string
    {
        $current = $input;
        for ($i = 0; $i < $maxPasses; $i++) {
            if (strpos($current, '%') === false) {
                break;
            }
            $decoded = rawurldecode($current);
            if ($decoded === $current) {
                $decoded = urldecode($current);
            }
            if ($decoded === $current) {
                break;
            }
            $current = $decoded;
        }
        return $current;
    }

    /**
     * Normalizes payload string across URL encoding, HTML entities,
     * null bytes, SQL comments, and whitespace collapsing.
     *
     * @param mixed $input
     * @return array{original: string, normalized: string}
     */
    public static function normalize($input): array
    {
        if (!is_string($input)) {
            $str = is_null($input) ? '' : (string)$input;
            return ['original' => $str, 'normalized' => $str];
        }

        // 0. Enforce ReDoS Safe Length Limit
        $bounded = mb_strlen($input, 'UTF-8') > self::MAX_INSPECTION_LENGTH
            ? mb_substr($input, 0, self::MAX_INSPECTION_LENGTH, 'UTF-8')
            : $input;

        // 1. Recursive URL Decoding (up to 3 passes)
        $processed = self::recursiveUrlDecode($bounded, 3);

        // 2. HTML Entity Decoding (named, decimal, hex)
        $processed = html_entity_decode($processed, ENT_QUOTES | ENT_HTML5, 'UTF-8');

        // 3. Strip Null Bytes
        $processed = str_replace(["\0", "\x00"], '', $processed);

        // 4. Strip Inline SQL Comments (/* ... */)
        $processed = preg_replace('/\/\*[\s\S]*?\*\//', ' ', $processed);

        // 5. Collapse Consecutive Whitespace
        $processed = trim(preg_replace('/\s+/', ' ', $processed));

        return [
            'original'   => $bounded,
            'normalized' => $processed,
        ];
    }
}
