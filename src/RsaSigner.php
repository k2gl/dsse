<?php

declare(strict_types=1);

namespace K2gl\Dsse;

use K2gl\Dsse\Exception\CryptoException;
use OpenSSLAsymmetricKey;

/**
 * {@see Signer} backed by RSASSA-PKCS1-v1_5 with SHA-256/384/512, using
 * ext-openssl. Emits the signature in its native wire form (no r||s recoding).
 *
 * RSASSA-PSS is intentionally not supported here (ext-openssl's openssl_sign
 * only does PKCS#1 v1.5 padding).
 */
final class RsaSigner implements Signer
{
    private function __construct(
        private readonly OpenSSLAsymmetricKey $privateKey,
        private readonly int $algorithm,
        private readonly ?string $keyId,
    ) {}

    /**
     * Load an RSA private key from a PEM string.
     *
     * @param 'sha256'|'sha384'|'sha512' $hashAlgorithm
     */
    public static function fromPem(string $pem, ?string $keyId = null, string $hashAlgorithm = 'sha256'): self
    {
        $key = openssl_pkey_get_private($pem);

        if ($key === false) {
            throw new CryptoException('Unable to load RSA private key: ' . self::lastError());
        }

        return new self($key, self::algorithm($hashAlgorithm), $keyId);
    }

    private static function lastError(): string
    {
        return openssl_error_string() ?: 'unknown error';
    }

    public function sign(string $message): string
    {
        $signature = '';

        if (openssl_sign($message, $signature, $this->privateKey, $this->algorithm) === false) {
            throw new CryptoException('RSA signing failed: ' . self::lastError());
        }

        return $signature;
    }

    public function keyId(): ?string
    {
        return $this->keyId;
    }

    private static function algorithm(string $hashAlgorithm): int
    {
        return match ($hashAlgorithm) {
            'sha256' => OPENSSL_ALGO_SHA256,
            'sha384' => OPENSSL_ALGO_SHA384,
            'sha512' => OPENSSL_ALGO_SHA512,
            default => throw new CryptoException(sprintf('Unsupported RSA hash algorithm "%s".', $hashAlgorithm)),
        };
    }
}
