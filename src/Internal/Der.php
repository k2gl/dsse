<?php

declare(strict_types=1);

namespace K2gl\Dsse\Internal;

/**
 * A minimal DER (ASN.1) encoder — just enough to build a SubjectPublicKeyInfo
 * from raw JWK components so ext-openssl can load it.
 *
 * OID constants are the content bytes only (without the leading 0x06/length),
 * so they can be compared against a parsed OID and wrapped with {@see self::oid()}.
 *
 * @internal
 */
final class Der
{
    /** 1.2.840.113549.1.1.1 rsaEncryption. */
    public const OID_RSA = "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01";

    /** 1.2.840.10045.2.1 id-ecPublicKey. */
    public const OID_EC = "\x2a\x86\x48\xce\x3d\x02\x01";

    /** 1.3.101.112 id-Ed25519. */
    public const OID_ED25519 = "\x2b\x65\x70";

    /** 1.2.840.10045.3.1.7 prime256v1 (NIST P-256). */
    public const OID_P256 = "\x2a\x86\x48\xce\x3d\x03\x01\x07";

    /** 1.3.132.0.34 secp384r1 (NIST P-384). */
    public const OID_P384 = "\x2b\x81\x04\x00\x22";

    /** 1.3.132.0.35 secp521r1 (NIST P-521). */
    public const OID_P521 = "\x2b\x81\x04\x00\x23";

    public const NULL = "\x05\x00";

    public static function sequence(string $contents): string
    {
        return "\x30" . self::length(strlen($contents)) . $contents;
    }

    public static function bitString(string $contents): string
    {
        return "\x03" . self::length(strlen($contents) + 1) . "\x00" . $contents;
    }

    public static function oid(string $content): string
    {
        return "\x06" . self::length(strlen($content)) . $content;
    }

    /** A DER INTEGER from an unsigned big-endian magnitude (minimal, sign-safe). */
    public static function integer(string $magnitude): string
    {
        $value = ltrim($magnitude, "\x00");

        if ($value === '') {
            $value = "\x00";
        }

        if ((ord($value[0]) & 0x80) !== 0) {
            $value = "\x00" . $value;
        }

        return "\x02" . self::length(strlen($value)) . $value;
    }

    public static function length(int $length): string
    {
        if ($length < 0x80) {
            return chr($length & 0xff);
        }
        $bytes = '';

        while ($length > 0) {
            $bytes = chr($length & 0xff) . $bytes;
            $length >>= 8;
        }

        return chr((0x80 | strlen($bytes)) & 0xff) . $bytes;
    }
}
