<?php

declare(strict_types=1);

namespace K2gl\Dsse\Tests;

use K2gl\Dsse\Exception\CryptoException;
use K2gl\Dsse\Internal\Jwk;
use K2gl\Dsse\Internal\Spki;
use K2gl\Dsse\KeyId;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

use function K2gl\PHPUnitFluentAssertions\fact;

#[CoversClass(KeyId::class)]
#[CoversClass(Spki::class)]
#[CoversClass(Jwk::class)]
#[CoversClass(CryptoException::class)]
final class KeyIdTest extends TestCase
{
    public function testSha256SpkiMatchesTheDerDigest(): void
    {
        $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
        fact($key)->notFalse();
        $pem = (string) openssl_pkey_get_details($key)['key'];
        $der = (string) base64_decode((string) preg_replace('/-----[^-]+-----|\s+/', '', $pem), true);

        fact(KeyId::sha256Spki($pem))->is(hash('sha256', $der));
    }

    /** RFC 8037 Appendix A.3 (Ed25519 JWK thumbprint). */
    public function testJwkThumbprintMatchesRfc8037OkpVector(): void
    {
        $jwk = ['kty' => 'OKP', 'crv' => 'Ed25519', 'x' => '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo'];

        fact(KeyId::jwkThumbprint($jwk))->is('kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k');
    }

    public function testJwkThumbprintUsesRfc7638RsaCanonicalisation(): void
    {
        $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
        fact($key)->notFalse();
        $rsa = openssl_pkey_get_details($key)['rsa'];
        $n = self::base64Url((string) $rsa['n']);
        $e = self::base64Url((string) $rsa['e']);

        // RFC 7638: hash the required members {e, kty, n}, lexicographically ordered, no whitespace.
        $canonical = sprintf('{"e":"%s","kty":"RSA","n":"%s"}', $e, $n);
        $expected = rtrim(strtr(base64_encode(hash('sha256', $canonical, true)), '+/', '-_'), '=');

        fact(KeyId::jwkThumbprint(['kty' => 'RSA', 'n' => $n, 'e' => $e]))->is($expected);
    }

    public function testJwkThumbprintRejectsUnsupportedKeyType(): void
    {
        $this->expectException(CryptoException::class);

        KeyId::jwkThumbprint(['kty' => 'oct', 'k' => 'AAAA']);
    }

    private static function base64Url(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }
}
