<?php

declare(strict_types=1);

namespace K2gl\Dsse;

use K2gl\Dsse\Exception\CryptoException;
use K2gl\Dsse\Internal\Asn1EcdsaSignature;

/**
 * {@see Verifier} for ECDSA over NIST P-256 (prime256v1) with SHA-256, using
 * ext-openssl. Accepts both raw r||s (64-byte) signatures, as produced by
 * {@see EcdsaP256Signer}, and ASN.1 DER signatures, as produced by OpenSSL and
 * carried in Sigstore bundles; the encoding is detected automatically.
 */
final class EcdsaP256Verifier implements Verifier
{
    private function __construct(private readonly \OpenSSLAsymmetricKey $publicKey)
    {
    }

    /** Load an EC P-256 public key from a PEM string. */
    public static function fromPem(string $pem): self
    {
        $key = openssl_pkey_get_public($pem);
        if ($key === false) {
            throw new CryptoException('Unable to load EC public key: ' . (openssl_error_string() ?: 'unknown error'));
        }
        return new self($key);
    }

    public function verify(string $message, string $signature): bool
    {
        // P-256 raw r||s is always exactly 64 bytes; anything else is treated as
        // ASN.1 DER (the form OpenSSL and Sigstore emit) and passed through verbatim.
        $der = strlen($signature) === 64
            ? Asn1EcdsaSignature::rawToDer($signature, 32)
            : $signature;

        return openssl_verify($message, $der, $this->publicKey, OPENSSL_ALGO_SHA256) === 1;
    }
}
