<?php

declare(strict_types=1);

namespace K2gl\Dsse\Internal;

use K2gl\Dsse\Exception\CryptoException;

/**
 * EMSA-PSS encoding and verification (RFC 8017 Section 9.1) with MGF1, the
 * salt as long as the hash — the parameters the Go and Python DSSE reference
 * implementations use. ext-openssl only pads PKCS#1 v1.5, so the RSA primitive
 * is used bare and the padding is done here.
 *
 * @internal
 */
final class Pss
{
    /** @return array{0: 'sha256'|'sha384'|'sha512', 1: 32|48|64} the hash algorithm and its output length */
    public static function hash(string $algorithm): array
    {
        return match ($algorithm) {
            'sha256' => ['sha256', 32],
            'sha384' => ['sha384', 48],
            'sha512' => ['sha512', 64],
            default => throw new CryptoException(sprintf('Unsupported RSA-PSS hash algorithm "%s".', $algorithm)),
        };
    }

    /** EMSA-PSS-ENCODE: the encoded message EM of emBits bits, salted with $salt. */
    public static function encode(string $message, int $emBits, string $hashAlgorithm, string $salt): string
    {
        [$hash, $hLen] = self::hash($hashAlgorithm);
        $sLen = strlen($salt);
        $emLen = intdiv($emBits + 7, 8);

        if ($emLen < $hLen + $sLen + 2) {
            throw new CryptoException('The RSA key is too small for RSA-PSS with this hash.');
        }
        $h = hash($hash, str_repeat("\x00", 8) . hash($hash, $message, true) . $salt, true);
        $db = str_repeat("\x00", $emLen - $sLen - $hLen - 2) . "\x01" . $salt;
        $maskedDb = $db ^ self::mgf1($h, $emLen - $hLen - 1, $hash);
        $maskedDb[0] = chr(ord($maskedDb[0]) & (0xff >> (8 * $emLen - $emBits)));

        return $maskedDb . $h . "\xbc";
    }

    /** EMSA-PSS-VERIFY: whether EM (emBits bits) is a valid encoding of $message. */
    public static function verify(string $message, string $em, int $emBits, string $hashAlgorithm): bool
    {
        [$hash, $hLen] = self::hash($hashAlgorithm);
        $sLen = $hLen;
        $emLen = intdiv($emBits + 7, 8);

        if (strlen($em) !== $emLen || $emLen < $hLen + $sLen + 2 || $em[$emLen - 1] !== "\xbc") {
            return false;
        }
        $maskedDb = substr($em, 0, $emLen - $hLen - 1);
        $h = substr($em, $emLen - $hLen - 1, $hLen);
        $topBits = 8 * $emLen - $emBits;

        if ($topBits > 0 && (ord($maskedDb[0]) & ((0xff << (8 - $topBits)) & 0xff)) !== 0) {
            return false;
        }
        $db = $maskedDb ^ self::mgf1($h, $emLen - $hLen - 1, $hash);
        $db[0] = chr(ord($db[0]) & (0xff >> $topBits));
        $psLen = $emLen - $sLen - $hLen - 2;

        if (substr($db, 0, $psLen) !== str_repeat("\x00", $psLen) || $db[$psLen] !== "\x01") {
            return false;
        }
        $salt = substr($db, $psLen + 1);
        $expected = hash($hash, str_repeat("\x00", 8) . hash($hash, $message, true) . $salt, true);

        return hash_equals($expected, $h);
    }

    private static function mgf1(string $seed, int $length, string $hash): string
    {
        $output = '';

        for ($counter = 0; strlen($output) < $length; $counter++) {
            $output .= hash($hash, $seed . pack('N', $counter), true);
        }

        return substr($output, 0, $length);
    }
}
