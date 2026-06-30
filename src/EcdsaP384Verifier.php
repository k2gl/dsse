<?php

declare(strict_types=1);

namespace K2gl\Dsse;

use K2gl\Dsse\Exception\CryptoException;
use K2gl\Dsse\Internal\Asn1EcdsaSignature;
use OpenSSLAsymmetricKey;

/**
 * {@see Verifier} for ECDSA over NIST P-384 (secp384r1) with SHA-384, using
 * ext-openssl. Accepts both raw r||s (96-byte) signatures, as produced by
 * {@see EcdsaP384Signer}, and ASN.1 DER signatures; the encoding is detected
 * automatically.
 */
final class EcdsaP384Verifier implements Verifier
{
    private function __construct(private readonly OpenSSLAsymmetricKey $publicKey) {}

    /** Load an EC P-384 public key from a PEM string. */
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
        // P-384 raw r||s is always exactly 96 bytes; anything else is treated as DER.
        $der = strlen($signature) === 96
            ? Asn1EcdsaSignature::rawToDer($signature, 48)
            : $signature;

        return openssl_verify($message, $der, $this->publicKey, OPENSSL_ALGO_SHA384) === 1;
    }
}
