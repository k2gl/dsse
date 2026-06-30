<?php

declare(strict_types=1);

namespace K2gl\Dsse;

use K2gl\Dsse\Exception\CryptoException;
use OpenSSLAsymmetricKey;

/**
 * {@see Verifier} for RSASSA-PKCS1-v1_5 with SHA-256/384/512, using ext-openssl.
 * The hash algorithm must match the one used to sign (default SHA-256).
 *
 * RSASSA-PSS is intentionally not supported here (ext-openssl's openssl_verify
 * only does PKCS#1 v1.5 padding).
 */
final class RsaVerifier implements Verifier
{
    private function __construct(
        private readonly OpenSSLAsymmetricKey $publicKey,
        private readonly int $algorithm,
    ) {}

    /**
     * Load an RSA public key from a PEM string.
     *
     * @param 'sha256'|'sha384'|'sha512' $hashAlgorithm
     */
    public static function fromPem(string $pem, string $hashAlgorithm = 'sha256'): self
    {
        $key = openssl_pkey_get_public($pem);

        if ($key === false) {
            throw new CryptoException('Unable to load RSA public key: ' . (openssl_error_string() ?: 'unknown error'));
        }

        return new self($key, self::algorithm($hashAlgorithm));
    }

    public function verify(string $message, string $signature): bool
    {
        return openssl_verify($message, $signature, $this->publicKey, $this->algorithm) === 1;
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
