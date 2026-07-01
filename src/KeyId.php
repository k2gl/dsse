<?php

declare(strict_types=1);

namespace K2gl\Dsse;

use K2gl\Dsse\Internal\Jwk;
use K2gl\Dsse\Internal\Spki;

/**
 * Public-key identifiers for the {@see Signature} keyId field.
 */
final class KeyId
{
    /**
     * Lower-case hex SHA-256 of the DER SubjectPublicKeyInfo — the public-key
     * fingerprint cosign and Sigstore use (equivalent to
     * `openssl pkey -pubin -outform DER | sha256sum`). Accepts a public-key PEM.
     */
    public static function sha256Spki(string $publicKeyPem): string
    {
        return hash('sha256', Spki::pemToDer($publicKeyPem));
    }

    /**
     * RFC 7638 JWK thumbprint: unpadded base64url SHA-256 of the key's canonical
     * member JSON. Supports EC, RSA and OKP (Ed25519) keys.
     *
     * @param array<string, mixed> $jwk
     */
    public static function jwkThumbprint(array $jwk): string
    {
        $hash = hash('sha256', Jwk::thumbprintJson($jwk), true);

        return rtrim(strtr(base64_encode($hash), '+/', '-_'), '=');
    }
}
