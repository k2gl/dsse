<?php

declare(strict_types=1);

namespace K2gl\Dsse\Tests;

use K2gl\Dsse\EcdsaP256Verifier;
use K2gl\Dsse\EcdsaP384Verifier;
use K2gl\Dsse\EcdsaP521Verifier;
use K2gl\Dsse\Ed25519Verifier;
use K2gl\Dsse\Exception\CryptoException;
use K2gl\Dsse\Internal\Der;
use K2gl\Dsse\Internal\Jwk;
use K2gl\Dsse\Internal\Spki;
use K2gl\Dsse\PublicKey;
use K2gl\Dsse\RsaVerifier;
use OpenSSLAsymmetricKey;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

use function K2gl\PHPUnitFluentAssertions\fact;

#[CoversClass(PublicKey::class)]
#[CoversClass(Spki::class)]
#[CoversClass(Jwk::class)]
#[CoversClass(Der::class)]
#[CoversClass(CryptoException::class)]
final class PublicKeyTest extends TestCase
{
    // RFC 8032 section 7.1, Test 1: public key, empty message, signature.
    private const ED_PUB_HEX = 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a';
    private const ED_SIG_HEX = 'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155'
        . '5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b';
    private const ED_JWK_X = '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo';

    #[DataProvider('ecProvider')]
    public function testFromPemLoadsEcCurves(string $curve, int $algorithm, string $expectedClass): void
    {
        $key = self::generateEc($curve);
        $signature = '';
        openssl_sign('the message', $signature, $key, $algorithm);
        $publicPem = (string) openssl_pkey_get_details($key)['key'];

        $verifier = PublicKey::fromPem($publicPem);

        fact($verifier)->instanceOf($expectedClass);
        fact($verifier->verify('the message', $signature))->true();
        fact($verifier->verify('tampered', $signature))->false();
    }

    public function testFromPemLoadsRsa(): void
    {
        $key = self::generateRsa();
        $signature = '';
        openssl_sign('the message', $signature, $key, OPENSSL_ALGO_SHA256);
        $publicPem = (string) openssl_pkey_get_details($key)['key'];

        $verifier = PublicKey::fromPem($publicPem);

        fact($verifier)->instanceOf(RsaVerifier::class);
        fact($verifier->verify('the message', $signature))->true();
    }

    public function testFromPemLoadsEd25519(): void
    {
        // A SubjectPublicKeyInfo for the RFC 8032 test key (id-Ed25519 + the 32-byte point).
        $pem = Spki::derToPem((string) hex2bin('302a300506032b6570032100' . self::ED_PUB_HEX));

        $verifier = PublicKey::fromPem($pem);

        fact($verifier)->instanceOf(Ed25519Verifier::class);
        fact($verifier->verify('', (string) hex2bin(self::ED_SIG_HEX)))->true();
        fact($verifier->verify('tampered', (string) hex2bin(self::ED_SIG_HEX)))->false();
    }

    public function testFromJwkLoadsOkpAndVerifiesRfc8032Vector(): void
    {
        $verifier = PublicKey::fromJwk(['kty' => 'OKP', 'crv' => 'Ed25519', 'x' => self::ED_JWK_X]);

        fact($verifier)->instanceOf(Ed25519Verifier::class);
        fact($verifier->verify('', (string) hex2bin(self::ED_SIG_HEX)))->true();
    }

    #[DataProvider('ecJwkProvider')]
    public function testFromJwkRoundTripsEc(string $curve, string $crv, int $algorithm, string $expectedClass): void
    {
        $key = self::generateEc($curve);
        $ec = openssl_pkey_get_details($key)['ec'];
        $jwk = ['kty' => 'EC', 'crv' => $crv, 'x' => self::base64Url((string) $ec['x']), 'y' => self::base64Url((string) $ec['y'])];
        $signature = '';
        openssl_sign('the message', $signature, $key, $algorithm);

        $verifier = PublicKey::fromJwk($jwk);

        fact($verifier)->instanceOf($expectedClass);
        fact($verifier->verify('the message', $signature))->true();
    }

    public function testFromJwkRoundTripsRsa(): void
    {
        $key = self::generateRsa();
        $rsa = openssl_pkey_get_details($key)['rsa'];
        $jwk = ['kty' => 'RSA', 'n' => self::base64Url((string) $rsa['n']), 'e' => self::base64Url((string) $rsa['e'])];
        $signature = '';
        openssl_sign('the message', $signature, $key, OPENSSL_ALGO_SHA256);

        $verifier = PublicKey::fromJwk($jwk);

        fact($verifier)->instanceOf(RsaVerifier::class);
        fact($verifier->verify('the message', $signature))->true();
    }

    public function testFromPemRejectsGarbage(): void
    {
        $this->expectException(CryptoException::class);

        PublicKey::fromPem('definitely not a key');
    }

    public function testFromJwkRejectsUnsupportedKeyType(): void
    {
        $this->expectException(CryptoException::class);

        PublicKey::fromJwk(['kty' => 'oct', 'k' => 'AAAA']);
    }

    public function testFromJwkRejectsMissingMember(): void
    {
        $this->expectException(CryptoException::class);

        PublicKey::fromJwk(['kty' => 'RSA', 'e' => 'AQAB']); // modulus missing
    }

    /**
     * @return array<string, array{string, int, class-string}>
     */
    public static function ecProvider(): array
    {
        return [
            'P-256' => ['prime256v1', OPENSSL_ALGO_SHA256, EcdsaP256Verifier::class],
            'P-384' => ['secp384r1', OPENSSL_ALGO_SHA384, EcdsaP384Verifier::class],
            'P-521' => ['secp521r1', OPENSSL_ALGO_SHA512, EcdsaP521Verifier::class],
        ];
    }

    /**
     * @return array<string, array{string, string, int, class-string}>
     */
    public static function ecJwkProvider(): array
    {
        return [
            'P-256' => ['prime256v1', 'P-256', OPENSSL_ALGO_SHA256, EcdsaP256Verifier::class],
            'P-521' => ['secp521r1', 'P-521', OPENSSL_ALGO_SHA512, EcdsaP521Verifier::class],
        ];
    }

    private static function generateEc(string $curve): OpenSSLAsymmetricKey
    {
        $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => $curve]);
        fact($key)->notFalse();

        return $key;
    }

    private static function generateRsa(): OpenSSLAsymmetricKey
    {
        $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
        fact($key)->notFalse();

        return $key;
    }

    private static function base64Url(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }
}
