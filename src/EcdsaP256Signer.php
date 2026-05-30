<?php

declare(strict_types=1);

namespace K2gl\Dsse;

use K2gl\Dsse\Exception\CryptoException;
use K2gl\Dsse\Internal\Asn1EcdsaSignature;

/**
 * {@see Signer} backed by ECDSA over NIST P-256 (prime256v1) with SHA-256, using
 * ext-openssl. Signatures are emitted in the raw r||s form (64 bytes) that
 * DSSE/JOSE/WebCrypto and Sigstore use, not OpenSSL's native DER.
 */
final class EcdsaP256Signer implements Signer
{
    private function __construct(
        private readonly \OpenSSLAsymmetricKey $privateKey,
        private readonly ?string $keyId,
    ) {
    }

    /** Load an EC P-256 private key from a PEM string. */
    public static function fromPem(string $pem, ?string $keyId = null): self
    {
        $key = openssl_pkey_get_private($pem);
        if ($key === false) {
            throw new CryptoException('Unable to load EC private key: ' . self::lastError());
        }
        return new self($key, $keyId);
    }

    public function sign(string $message): string
    {
        $der = '';
        if (openssl_sign($message, $der, $this->privateKey, OPENSSL_ALGO_SHA256) === false) {
            throw new CryptoException('ECDSA signing failed: ' . self::lastError());
        }
        return Asn1EcdsaSignature::derToRaw($der, 32);
    }

    public function keyId(): ?string
    {
        return $this->keyId;
    }

    private static function lastError(): string
    {
        return openssl_error_string() ?: 'unknown error';
    }
}
