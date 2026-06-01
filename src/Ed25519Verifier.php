<?php

declare(strict_types=1);

namespace K2gl\Dsse;

use K2gl\Dsse\Exception\CryptoException;

/**
 * {@see Verifier} for Ed25519 (ext-sodium). Expects a 32-byte libsodium public
 * key as produced by sodium_crypto_sign_publickey().
 */
final class Ed25519Verifier implements Verifier
{
    /**
     * @param non-empty-string $publicKey libsodium public key from sodium_crypto_sign_publickey()
     */
    public function __construct(private readonly string $publicKey)
    {
        if (strlen($publicKey) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES) {
            throw new CryptoException(
                'Ed25519 public key must be ' . SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES . ' bytes.'
            );
        }
    }

    public function verify(string $message, string $signature): bool
    {
        if (strlen($signature) !== SODIUM_CRYPTO_SIGN_BYTES) {
            return false;
        }

        return sodium_crypto_sign_verify_detached($signature, $message, $this->publicKey);
    }
}
