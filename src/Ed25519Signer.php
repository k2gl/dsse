<?php

declare(strict_types=1);

namespace K2gl\Dsse;

use K2gl\Dsse\Exception\CryptoException;

/**
 * {@see Signer} backed by Ed25519 (ext-sodium). Expects a libsodium secret key
 * as produced by sodium_crypto_sign_keypair() / sodium_crypto_sign_secretkey().
 */
final class Ed25519Signer implements Signer
{
    /**
     * @param non-empty-string $secretKey libsodium secret key from
     *                                    sodium_crypto_sign_keypair() / sodium_crypto_sign_secretkey()
     */
    public function __construct(
        private readonly string $secretKey,
        private readonly ?string $keyId = null,
    ) {
        if (strlen($secretKey) !== SODIUM_CRYPTO_SIGN_SECRETKEYBYTES) {
            throw new CryptoException(
                'Ed25519 secret key must be ' . SODIUM_CRYPTO_SIGN_SECRETKEYBYTES . ' bytes.'
            );
        }
    }

    public function sign(string $message): string
    {
        return sodium_crypto_sign_detached($message, $this->secretKey);
    }

    public function keyId(): ?string
    {
        return $this->keyId;
    }
}
