<?php

declare(strict_types=1);

namespace K2gl\Dsse;

use K2gl\Dsse\Exception\CryptoException;
use K2gl\Dsse\Internal\Asn1EcdsaSignature;
use OpenSSLAsymmetricKey;

/**
 * {@see Signer} backed by ECDSA over NIST P-521 (secp521r1) with SHA-512, using
 * ext-openssl. By default signatures are emitted in the raw r||s form (132 bytes) that
 * DSSE/JOSE/WebCrypto and Sigstore use, not OpenSSL's native DER.
 */
final class EcdsaP521Signer implements Signer
{
    private function __construct(
        private readonly OpenSSLAsymmetricKey $privateKey,
        private readonly ?string $keyId,
        private readonly SignatureEncoding $encoding,
    ) {}

    /**
     * Load an EC P-521 private key from a PEM string. Signatures come out as
     * raw `r||s` unless `$encoding` asks for ASN.1 DER.
     */
    public static function fromPem(string $pem, ?string $keyId = null, SignatureEncoding $encoding = SignatureEncoding::Raw): self
    {
        $key = openssl_pkey_get_private($pem);

        if ($key === false) {
            throw new CryptoException('Unable to load EC private key: ' . self::lastError());
        }

        return new self($key, $keyId, $encoding);
    }

    public function sign(string $message): string
    {
        $der = '';

        if (openssl_sign($message, $der, $this->privateKey, OPENSSL_ALGO_SHA512) === false) {
            throw new CryptoException('ECDSA signing failed: ' . self::lastError());
        }

        return $this->encoding === SignatureEncoding::Der ? $der : Asn1EcdsaSignature::derToRaw($der, 66);
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
