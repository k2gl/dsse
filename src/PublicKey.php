<?php

declare(strict_types=1);

namespace K2gl\Dsse;

use K2gl\Dsse\Exception\CryptoException;
use K2gl\Dsse\Internal\Der;
use K2gl\Dsse\Internal\Jwk;
use K2gl\Dsse\Internal\Spki;

/**
 * Loads a public key and returns the matching {@see Verifier}, detecting the
 * algorithm (and EC curve) automatically — so you can hand a verifier a key from
 * a PEM file or a JWKS endpoint without knowing its type up front.
 *
 * RSA keys carry no hash in the key material, so they default to SHA-256; use
 * {@see RsaVerifier::fromPem()} directly for SHA-384/512.
 */
final class PublicKey
{
    /**
     * Load a public key from a PEM (SubjectPublicKeyInfo). Supports RSA, ECDSA
     * over P-256/P-384/P-521, and Ed25519.
     */
    public static function fromPem(string $pem): Verifier
    {
        // Detect the algorithm and curve from the SubjectPublicKeyInfo itself. The
        // uncompressed EC point length (65/97/133 bytes = P-256/384/521) is
        // unambiguous and, unlike OpenSSL's reported curve name, does not vary with
        // the OpenSSL version or named-vs-explicit curve parameters.
        $info = Spki::describe(Spki::pemToDer($pem));
        $algorithm = $info['algorithm'];

        if ($algorithm === Der::OID_RSA) {
            return RsaVerifier::fromPem($pem);
        }

        if ($algorithm === Der::OID_ED25519) {
            $key = $info['publicKey'];

            if ($key === '' || strlen($key) !== 32) {
                throw new CryptoException('Invalid Ed25519 public key.');
            }

            return new Ed25519Verifier($key);
        }

        if ($algorithm === Der::OID_EC) {
            return match (strlen($info['publicKey'])) {
                65 => EcdsaP256Verifier::fromPem($pem),
                97 => EcdsaP384Verifier::fromPem($pem),
                133 => EcdsaP521Verifier::fromPem($pem),
                default => throw new CryptoException('Unsupported EC curve: expected P-256, P-384 or P-521.'),
            };
        }

        throw new CryptoException('Unsupported public key: expected RSA, ECDSA (P-256/384/521) or Ed25519.');
    }

    /**
     * Load a public key from a JWK (RFC 7517). Supports `EC` (P-256/384/521),
     * `RSA`, and `OKP` (Ed25519).
     *
     * @param array<string, mixed> $jwk
     */
    public static function fromJwk(array $jwk): Verifier
    {
        return Jwk::toVerifier($jwk);
    }
}
