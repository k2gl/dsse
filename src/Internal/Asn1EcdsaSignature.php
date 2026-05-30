<?php

declare(strict_types=1);

namespace K2gl\Dsse\Internal;

use K2gl\Dsse\Exception\CryptoException;

/**
 * Converts ECDSA signatures between OpenSSL's ASN.1 DER encoding and the raw,
 * fixed-width r||s encoding (IEEE P1363) that DSSE/JOSE/WebCrypto/Sigstore use.
 *
 * @internal
 */
final class Asn1EcdsaSignature
{
    /**
     * DER SEQUENCE { INTEGER r, INTEGER s } -> r||s, each left-padded to $size bytes.
     */
    public static function derToRaw(string $der, int $size): string
    {
        $offset = 0;
        if (self::byte($der, $offset++) !== 0x30) {
            throw new CryptoException('Invalid ECDSA signature: expected a DER SEQUENCE.');
        }
        self::readLength($der, $offset); // sequence length, not needed
        $r = self::readInteger($der, $offset);
        $s = self::readInteger($der, $offset);

        return self::pad($r, $size) . self::pad($s, $size);
    }

    /**
     * r||s (each $size bytes) -> DER SEQUENCE { INTEGER r, INTEGER s }.
     */
    public static function rawToDer(string $raw, int $size): string
    {
        if (strlen($raw) !== 2 * $size) {
            throw new CryptoException('Invalid raw ECDSA signature length.');
        }
        $seq = self::encodeInteger(substr($raw, 0, $size))
            . self::encodeInteger(substr($raw, $size, $size));

        return "\x30" . self::encodeLength(strlen($seq)) . $seq;
    }

    private static function byte(string $bytes, int $index): int
    {
        if (!isset($bytes[$index])) {
            throw new CryptoException('Invalid ECDSA signature: unexpected end of data.');
        }
        return ord($bytes[$index]);
    }

    private static function readLength(string $bytes, int &$offset): int
    {
        $first = self::byte($bytes, $offset++);
        if ($first < 0x80) {
            return $first;
        }
        $count = $first & 0x7f;
        $length = 0;
        for ($i = 0; $i < $count; $i++) {
            $length = ($length << 8) | self::byte($bytes, $offset++);
        }
        return $length;
    }

    private static function readInteger(string $bytes, int &$offset): string
    {
        if (self::byte($bytes, $offset++) !== 0x02) {
            throw new CryptoException('Invalid ECDSA signature: expected a DER INTEGER.');
        }
        $length = self::readLength($bytes, $offset);
        $value = substr($bytes, $offset, $length);
        if (strlen($value) !== $length) {
            throw new CryptoException('Invalid ECDSA signature: truncated INTEGER.');
        }
        $offset += $length;

        return $value;
    }

    private static function pad(string $value, int $size): string
    {
        $value = ltrim($value, "\x00");
        if (strlen($value) > $size) {
            throw new CryptoException('Invalid ECDSA signature: integer larger than the curve size.');
        }
        return str_pad($value, $size, "\x00", STR_PAD_LEFT);
    }

    private static function encodeInteger(string $value): string
    {
        $value = ltrim($value, "\x00");
        if ($value === '') {
            $value = "\x00";
        }
        if ((ord($value[0]) & 0x80) !== 0) {
            $value = "\x00" . $value;
        }
        return "\x02" . self::encodeLength(strlen($value)) . $value;
    }

    private static function encodeLength(int $length): string
    {
        if ($length < 0x80) {
            return chr($length);
        }
        $bytes = '';
        while ($length > 0) {
            $bytes = chr($length & 0xff) . $bytes;
            $length >>= 8;
        }
        return chr(0x80 | strlen($bytes)) . $bytes;
    }
}
