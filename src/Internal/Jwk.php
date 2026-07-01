<?php

declare(strict_types=1);

namespace K2gl\Dsse\Internal;

use K2gl\Dsse\EcdsaP256Verifier;
use K2gl\Dsse\EcdsaP384Verifier;
use K2gl\Dsse\EcdsaP521Verifier;
use K2gl\Dsse\Ed25519Verifier;
use K2gl\Dsse\Exception\CryptoException;
use K2gl\Dsse\RsaVerifier;
use K2gl\Dsse\Verifier;

/**
 * JWK (RFC 7517/7518, EC/RSA/OKP) -> {@see Verifier}, plus the RFC 7638
 * thumbprint input (the canonical required-member JSON).
 *
 * @internal
 */
final class Jwk
{
    /**
     * @param array<string, mixed> $jwk
     */
    public static function toVerifier(array $jwk): Verifier
    {
        $kty = self::member($jwk, 'kty');

        return match ($kty) {
            'OKP' => self::okp($jwk),
            'EC' => self::ec($jwk),
            'RSA' => self::rsa($jwk),
            default => throw new CryptoException(sprintf('Unsupported JWK key type "%s".', $kty)),
        };
    }

    /**
     * RFC 7638 canonical member JSON: the required members only, ordered
     * lexicographically, with no insignificant whitespace.
     *
     * @param array<string, mixed> $jwk
     */
    public static function thumbprintJson(array $jwk): string
    {
        $kty = self::member($jwk, 'kty');

        $members = match ($kty) {
            'OKP' => ['crv' => self::member($jwk, 'crv'), 'kty' => 'OKP', 'x' => self::member($jwk, 'x')],
            'EC' => ['crv' => self::member($jwk, 'crv'), 'kty' => 'EC', 'x' => self::member($jwk, 'x'), 'y' => self::member($jwk, 'y')],
            'RSA' => ['e' => self::member($jwk, 'e'), 'kty' => 'RSA', 'n' => self::member($jwk, 'n')],
            default => throw new CryptoException(sprintf('Unsupported JWK key type "%s".', $kty)),
        };

        return json_encode($members, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
    }

    /**
     * @param array<string, mixed> $jwk
     */
    private static function okp(array $jwk): Ed25519Verifier
    {
        if (self::member($jwk, 'crv') !== 'Ed25519') {
            throw new CryptoException('Only the Ed25519 OKP curve is supported.');
        }

        $key = self::base64Url(self::member($jwk, 'x'));

        if ($key === '') {
            throw new CryptoException('Empty Ed25519 public key in JWK.');
        }

        return new Ed25519Verifier($key);
    }

    /**
     * @param array<string, mixed> $jwk
     */
    private static function ec(array $jwk): Verifier
    {
        $crv = self::member($jwk, 'crv');

        return match ($crv) {
            'P-256' => EcdsaP256Verifier::fromPem(self::ecPem($jwk, Der::OID_P256, 32)),
            'P-384' => EcdsaP384Verifier::fromPem(self::ecPem($jwk, Der::OID_P384, 48)),
            'P-521' => EcdsaP521Verifier::fromPem(self::ecPem($jwk, Der::OID_P521, 66)),
            default => throw new CryptoException(sprintf('Unsupported EC curve "%s".', $crv)),
        };
    }

    /**
     * @param array<string, mixed> $jwk
     */
    private static function rsa(array $jwk): RsaVerifier
    {
        return RsaVerifier::fromPem(Spki::rsaPem(
            self::base64Url(self::member($jwk, 'n')),
            self::base64Url(self::member($jwk, 'e')),
        ));
    }

    /**
     * @param array<string, mixed> $jwk
     */
    private static function ecPem(array $jwk, string $curveOid, int $size): string
    {
        $x = self::coordinate(self::base64Url(self::member($jwk, 'x')), $size);
        $y = self::coordinate(self::base64Url(self::member($jwk, 'y')), $size);

        return Spki::ecPem($curveOid, "\x04" . $x . $y);
    }

    private static function coordinate(string $bytes, int $size): string
    {
        if (strlen($bytes) > $size) {
            throw new CryptoException('EC coordinate is larger than the curve size.');
        }

        return str_pad($bytes, $size, "\x00", STR_PAD_LEFT);
    }

    private static function base64Url(string $value): string
    {
        $base64 = strtr($value, '-_', '+/');
        $base64 .= str_repeat('=', (4 - strlen($base64) % 4) % 4);
        $decoded = base64_decode($base64, true);

        if ($decoded === false) {
            throw new CryptoException('Invalid base64url value in JWK.');
        }

        return $decoded;
    }

    /**
     * @param array<string, mixed> $jwk
     */
    private static function member(array $jwk, string $key): string
    {
        $value = $jwk[$key] ?? null;

        if (! is_string($value) || $value === '') {
            throw new CryptoException(sprintf('JWK is missing the required "%s" member.', $key));
        }

        return $value;
    }
}
