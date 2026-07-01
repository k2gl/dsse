<?php

declare(strict_types=1);

namespace K2gl\Dsse\Internal;

use K2gl\Dsse\Exception\CryptoException;

/**
 * SubjectPublicKeyInfo helpers: PEM <-> DER, reading the algorithm identifier out
 * of a key (to detect Ed25519), and building an SPKI PEM from raw JWK components.
 *
 * @internal
 */
final class Spki
{
    public static function pemToDer(string $pem): string
    {
        if (preg_match('/-----BEGIN [A-Z0-9 ]+-----(.+?)-----END [A-Z0-9 ]+-----/s', $pem, $matches) !== 1) {
            throw new CryptoException('Invalid PEM: no base64 body found.');
        }

        $der = base64_decode((string) preg_replace('/\s+/', '', $matches[1]), true);

        if ($der === false) {
            throw new CryptoException('Invalid PEM: body is not valid base64.');
        }

        return $der;
    }

    public static function derToPem(string $der): string
    {
        return "-----BEGIN PUBLIC KEY-----\n"
            . chunk_split(base64_encode($der), 64, "\n")
            . "-----END PUBLIC KEY-----\n";
    }

    /**
     * Read the algorithm OID and the raw public-key bytes out of an SPKI DER.
     *
     * @return array{algorithm: string, publicKey: string}
     */
    public static function describe(string $der): array
    {
        $offset = 0;
        $spki = self::read($der, $offset, 0x30, 'SubjectPublicKeyInfo');

        $inner = 0;
        $algorithmIdentifier = self::read($spki, $inner, 0x30, 'AlgorithmIdentifier');

        $algorithmOffset = 0;
        $algorithm = self::read($algorithmIdentifier, $algorithmOffset, 0x06, 'algorithm OID');

        $bitString = self::read($spki, $inner, 0x03, 'subjectPublicKey');

        if ($bitString === '' || $bitString[0] !== "\x00") {
            throw new CryptoException('Invalid DER: unsupported subjectPublicKey bit string.');
        }

        return ['algorithm' => $algorithm, 'publicKey' => substr($bitString, 1)];
    }

    public static function ecPem(string $curveOid, string $point): string
    {
        return self::derToPem(Der::sequence(
            Der::sequence(Der::oid(Der::OID_EC) . Der::oid($curveOid))
            . Der::bitString($point)
        ));
    }

    public static function rsaPem(string $modulus, string $exponent): string
    {
        $rsaPublicKey = Der::sequence(Der::integer($modulus) . Der::integer($exponent));

        return self::derToPem(Der::sequence(
            Der::sequence(Der::oid(Der::OID_RSA) . Der::NULL)
            . Der::bitString($rsaPublicKey)
        ));
    }

    /** Read one TLV of the expected tag and return its content, advancing $offset. */
    private static function read(string $der, int &$offset, int $expectedTag, string $what): string
    {
        if (! isset($der[$offset]) || ord($der[$offset]) !== $expectedTag) {
            throw new CryptoException("Invalid DER: expected {$what}.");
        }
        $offset++;
        $length = self::readLength($der, $offset);
        $content = substr($der, $offset, $length);

        if (strlen($content) !== $length) {
            throw new CryptoException("Invalid DER: truncated {$what}.");
        }
        $offset += $length;

        return $content;
    }

    private static function readLength(string $der, int &$offset): int
    {
        if (! isset($der[$offset])) {
            throw new CryptoException('Invalid DER: truncated length.');
        }
        $first = ord($der[$offset++]);

        if ($first < 0x80) {
            return $first;
        }
        $count = $first & 0x7f;
        $length = 0;

        for ($i = 0; $i < $count; $i++) {
            if (! isset($der[$offset])) {
                throw new CryptoException('Invalid DER: truncated length.');
            }
            $length = ($length << 8) | ord($der[$offset++]);
        }

        return $length;
    }
}
