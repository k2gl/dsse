<?php

declare(strict_types=1);

namespace K2gl\Dsse;

use K2gl\Dsse\Exception\CryptoException;
use K2gl\Dsse\Internal\Pss;
use OpenSSLAsymmetricKey;

/**
 * {@see Signer} backed by RSASSA-PSS with SHA-256/384/512 (MGF1 with the same
 * hash, a random salt as long as the hash), using ext-openssl for the RSA
 * primitive and EMSA-PSS done here. Produces what the Go and Python DSSE
 * reference implementations verify as `rsassa-pss-sha256` and friends.
 */
final class RsaPssSigner implements Signer
{
    private function __construct(
        private readonly OpenSSLAsymmetricKey $privateKey,
        private readonly int $modulusBits,
        private readonly string $hashAlgorithm,
        private readonly ?string $keyId,
    ) {}

    /**
     * Load an RSA private key from a PEM string.
     *
     * @param 'sha256'|'sha384'|'sha512' $hashAlgorithm
     */
    public static function fromPem(string $pem, ?string $keyId = null, string $hashAlgorithm = 'sha256'): self
    {
        Pss::hash($hashAlgorithm);
        $key = openssl_pkey_get_private($pem);

        if ($key === false) {
            throw new CryptoException('Unable to load RSA private key: ' . (openssl_error_string() ?: 'unknown error'));
        }
        $details = openssl_pkey_get_details($key);

        if (! is_array($details) || ($details['type'] ?? null) !== OPENSSL_KEYTYPE_RSA || ! is_int($details['bits'] ?? null)) {
            throw new CryptoException('The private key is not an RSA key.');
        }

        return new self($key, $details['bits'], $hashAlgorithm, $keyId);
    }

    public function sign(string $message): string
    {
        [, $hLen] = Pss::hash($this->hashAlgorithm);
        $em = Pss::encode($message, $this->modulusBits - 1, $this->hashAlgorithm, random_bytes($hLen));
        $signature = '';

        // The bare primitive takes exactly the modulus length; EM can be one byte short of it.
        $padded = str_pad($em, intdiv($this->modulusBits + 7, 8), "\x00", STR_PAD_LEFT);

        if (openssl_private_encrypt($padded, $signature, $this->privateKey, OPENSSL_NO_PADDING) === false) {
            throw new CryptoException('RSA-PSS signing failed: ' . (openssl_error_string() ?: 'unknown error'));
        }

        return $signature;
    }

    public function keyId(): ?string
    {
        return $this->keyId;
    }
}
