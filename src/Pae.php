<?php

declare(strict_types=1);

namespace K2gl\Dsse;

/**
 * PAE (Pre-Authentication Encoding) from the DSSE protocol: the exact byte
 * string that is signed and verified.
 *
 *   PAE(type, body) = "DSSEv1" SP LEN(type) SP type SP LEN(body) SP body
 *
 * where SP is a single ASCII space and LEN(s) is the byte length of s in ASCII
 * decimal with no leading zeros. Because the lengths are byte counts, the
 * encoding is binary-safe and unambiguous regardless of the payload contents.
 *
 * @see https://github.com/secure-systems-lab/dsse/blob/master/protocol.md
 */
final class Pae
{
    private const PREFIX = 'DSSEv1';

    public static function encode(string $payloadType, string $payload): string
    {
        return self::PREFIX
            . ' ' . strlen($payloadType) . ' ' . $payloadType
            . ' ' . strlen($payload) . ' ' . $payload;
    }
}
