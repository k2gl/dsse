<?php

declare(strict_types=1);

namespace K2gl\Dsse;

use K2gl\Dsse\Exception\CryptoException;
use K2gl\Dsse\Internal\Pss;
use OpenSSLAsymmetricKey;

/**
 * {@see Verifier} for RSASSA-PSS with SHA-256/384/512 (MGF1 with the same hash,
 * salt as long as the hash) — the RSA scheme the Go and Python DSSE reference
 * implementations sign with. ext-openssl has no PSS verify, so the RSA
 * primitive is used bare and EMSA-PSS is checked here.
 */
final class RsaPssVerifier implements Verifier
{
    private function __construct(
        private readonly OpenSSLAsymmetricKey $publicKey,
        private readonly int $modulusBits,
        private readonly string $hashAlgorithm,
    ) {}

    /**
     * Load an RSA public key from a PEM string.
     *
     * @param 'sha256'|'sha384'|'sha512' $hashAlgorithm
     */
    public static function fromPem(string $pem, string $hashAlgorithm = 'sha256'): self
    {
        Pss::hash($hashAlgorithm);
        $key = openssl_pkey_get_public($pem);

        if ($key === false) {
            throw new CryptoException('Unable to load RSA public key: ' . (openssl_error_string() ?: 'unknown error'));
        }
        $details = openssl_pkey_get_details($key);

        if (! is_array($details) || ($details['type'] ?? null) !== OPENSSL_KEYTYPE_RSA || ! is_int($details['bits'] ?? null)) {
            throw new CryptoException('The public key is not an RSA key.');
        }

        return new self($key, $details['bits'], $hashAlgorithm);
    }

    public function verify(string $message, string $signature): bool
    {
        $k = intdiv($this->modulusBits + 7, 8);

        if (strlen($signature) !== $k) {
            return false;
        }
        $em = '';

        // OPENSSL_NO_PADDING gives the raw RSA result (s^e mod n): the encoded message.
        if (openssl_public_decrypt($signature, $em, $this->publicKey, OPENSSL_NO_PADDING) === false) {
            return false;
        }
        $emLen = intdiv($this->modulusBits - 1 + 7, 8);

        // The primitive yields k bytes; EM is one shorter when the modulus length is 1 mod 8.
        if (strlen($em) > $emLen) {
            if (ltrim(substr($em, 0, strlen($em) - $emLen), "\x00") !== '') {
                return false;
            }
            $em = substr($em, -$emLen);
        }

        return Pss::verify($message, str_pad($em, $emLen, "\x00", STR_PAD_LEFT), $this->modulusBits - 1, $this->hashAlgorithm);
    }
}
