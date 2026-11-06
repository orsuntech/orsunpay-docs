<?php

declare(strict_types=1);

namespace OrsunPayExample;

/**
 * Authenticate exact request bytes before parsing JSON or performing business actions.
 *
 * Capture the body with file_get_contents('php://input') at your HTTP boundary. Enforce a
 * body-size limit and reject duplicate signature header lines there. Pass the full issued
 * UTF-8 secret strings unchanged; do not hex-decode their suffixes. A true result proves
 * the signature only, not the event schema or ownership. Never log these inputs.
 *
 * Requires 64-bit PHP 8 with its standard hash extension. No work runs when imported.
 * Omit $now to use the current Unix time in seconds; an explicit non-integer is invalid.
 *
 * @param mixed $rawBody Exact binary string, never a decoded object or array.
 * @param mixed $header A single OrsunPay-Signature header string, at most 4096 bytes.
 * @param mixed $secrets Nonempty list of locally accepted secret strings.
 * @param mixed $now Optional integer Unix timestamp in seconds.
 */
function verifyWebhook($rawBody, $header, $secrets, $now = null): bool
{
    if (PHP_INT_SIZE < 8 || !is_string($rawBody) || !is_string($header) || strlen($header) > 4096) {
        return false;
    }
    if (!is_array($secrets) || count($secrets) === 0) {
        return false;
    }
    // array_is_list requires PHP 8.1; retain compatibility with PHP 8.0.
    $index = 0;
    foreach ($secrets as $key => $_secret) {
        if ($key !== $index++) {
            return false;
        }
    }
    if (func_num_args() < 4) {
        $now = time();
    }
    if (!is_int($now) || $now < -9007199254740991 || $now > 9007199254740991) {
        return false;
    }

    $timestampText = null;
    $signatures = [];
    // ECMAScript String.trim whitespace, without PHP trim's extra NUL stripping.
    $space = '[\x{0009}-\x{000D}\x{0020}\x{00A0}\x{1680}\x{2000}-\x{200A}\x{2028}\x{2029}\x{202F}\x{205F}\x{3000}\x{FEFF}]';
    foreach (explode(',', $header) as $part) {
        $part = preg_replace('/\A' . $space . '+|' . $space . '+\z/u', '', $part);
        if ($part === null) {
            return false;
        }
        if (str_starts_with($part, 't=')) {
            if ($timestampText !== null || preg_match('/\At=[0-9]+\z/', $part) !== 1) {
                return false;
            }
            $timestampText = substr($part, 2);
        } elseif (preg_match('/\Av1=[0-9a-f]{64}\z/i', $part) === 1) {
            $signature = hex2bin(substr($part, 3));
            if ($signature !== false) {
                $signatures[] = $signature;
            }
        }
    }
    if ($timestampText === null || count($signatures) === 0) {
        return false;
    }

    // Compare decimal text before casting: PHP must not saturate an oversized integer.
    // Leading zeroes are allowed, but remain in the HMAC's signed timestamp text.
    $normalized = ltrim($timestampText, '0');
    if ($normalized === '') {
        $normalized = '0';
    }
    $maximum = '9007199254740991';
    if (strlen($normalized) > strlen($maximum)
        || (strlen($normalized) === strlen($maximum) && strcmp($normalized, $maximum) > 0)) {
        return false;
    }
    $timestamp = (int) $normalized;
    if (abs($now - $timestamp) > 300) {
        return false;
    }

    foreach ($secrets as $secret) {
        if (!is_string($secret) || $secret === '') {
            continue;
        }
        $expected = hash_hmac('sha256', $timestampText . '.' . $rawBody, $secret, true);
        foreach ($signatures as $signature) {
            // Both operands are exactly 32 bytes; compare without data-dependent byte exits.
            if (hash_equals($expected, $signature)) {
                return true;
            }
        }
    }
    return false;
}
