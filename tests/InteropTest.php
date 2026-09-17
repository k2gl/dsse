<?php

declare(strict_types=1);

namespace K2gl\Dsse\Tests;

use K2gl\Dsse\EcdsaP256Verifier;
use K2gl\Dsse\EcdsaP384Verifier;
use K2gl\Dsse\EcdsaP521Verifier;
use K2gl\Dsse\Ed25519Verifier;
use K2gl\Dsse\Envelope;
use K2gl\Dsse\Exception\SignatureVerificationFailed;
use K2gl\Dsse\Internal\Asn1EcdsaSignature;
use K2gl\Dsse\Internal\Der;
use K2gl\Dsse\Internal\Jwk;
use K2gl\Dsse\Internal\Pss;
use K2gl\Dsse\Internal\Spki;
use K2gl\Dsse\KeyId;
use K2gl\Dsse\Pae;
use K2gl\Dsse\PublicKey;
use K2gl\Dsse\RsaPssVerifier;
use K2gl\Dsse\RsaVerifier;
use K2gl\Dsse\Signature;
use K2gl\Dsse\Verifier;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use RuntimeException;

use function K2gl\PHPUnitFluentAssertions\fact;

/**
 * Envelopes produced by the Go (go-securesystemslib) and Python
 * (securesystemslib) reference implementations, verified here. The fixtures in
 * tests/fixtures/interop come from tests/interop; the CI interop job regenerates
 * them with the upstream code and points DSSE_INTEROP_DIR at the result.
 */
#[CoversClass(Envelope::class)]
#[CoversClass(Signature::class)]
#[CoversClass(Pae::class)]
#[CoversClass(PublicKey::class)]
#[CoversClass(Spki::class)]
#[CoversClass(Jwk::class)]
#[CoversClass(Der::class)]
#[CoversClass(KeyId::class)]
#[CoversClass(EcdsaP256Verifier::class)]
#[CoversClass(EcdsaP384Verifier::class)]
#[CoversClass(EcdsaP521Verifier::class)]
#[CoversClass(Ed25519Verifier::class)]
#[CoversClass(RsaVerifier::class)]
#[CoversClass(RsaPssVerifier::class)]
#[CoversClass(Pss::class)]
#[CoversClass(Asn1EcdsaSignature::class)]
final class InteropTest extends TestCase
{
    #[DataProvider('fixtures')]
    public function testVerifiesAnUpstreamEnvelope(string $file): void
    {
        // arrange
        $fixture = self::fixture($file);
        $envelope = Envelope::fromJson(json_encode($fixture['envelope'], JSON_THROW_ON_ERROR));
        $verifier = self::verifierFor($fixture['scheme'], $fixture['publicKeyPem']);

        // act
        $payload = $envelope->verify($verifier);

        // assert
        fact($payload)->is(base64_decode($fixture['envelope']['payload'], true));
        fact($envelope->signatures[0]->keyId)->is($fixture['keyid']);
    }

    #[DataProvider('fixtures')]
    public function testRejectsAnUpstreamEnvelopeWithATamperedPayload(string $file): void
    {
        // arrange
        $fixture = self::fixture($file);
        $envelope = Envelope::fromJson(json_encode($fixture['envelope'], JSON_THROW_ON_ERROR));
        $tampered = new Envelope($envelope->payload . ' ', $envelope->payloadType, $envelope->signatures);
        $verifier = self::verifierFor($fixture['scheme'], $fixture['publicKeyPem']);

        // act + assert
        fact(static fn () => $tampered->verify($verifier))->throws(SignatureVerificationFailed::class);
    }

    #[DataProvider('fixtures')]
    public function testTheKeyLoadsWithoutNamingItsAlgorithm(string $file): void
    {
        $fixture = self::fixture($file);

        if (str_starts_with($fixture['scheme'], 'rsa')) {
            // A PEM does not say PKCS#1 v1.5 or PSS; PublicKey::fromPem() picks v1.5.
            fact(PublicKey::fromPem($fixture['publicKeyPem']))->instanceOf(RsaVerifier::class);

            return;
        }
        $envelope = Envelope::fromJson(json_encode($fixture['envelope'], JSON_THROW_ON_ERROR));

        fact($envelope->verify(PublicKey::fromPem($fixture['publicKeyPem'])))->is($envelope->payload);
    }

    /** @return iterable<string, array{string}> */
    public static function fixtures(): iterable
    {
        $files = glob(self::directory() . '/*.json');
        fact($files)->notFalse();
        fact($files)->isNotEmptyArray();

        foreach ((array) $files as $file) {
            yield basename((string) $file, '.json') => [(string) $file];
        }
    }

    private static function directory(): string
    {
        $configured = getenv('DSSE_INTEROP_DIR');

        return is_string($configured) && $configured !== '' ? $configured : __DIR__ . '/fixtures/interop';
    }

    /**
     * @return array{implementation: string, scheme: string, keyid: string, publicKeyPem: string, envelope: array{payload: string, payloadType: string, signatures: list<array{keyid: string, sig: string}>}}
     */
    private static function fixture(string $file): array
    {
        $json = file_get_contents($file);
        fact($json)->isString();

        /** @var array{implementation: string, scheme: string, keyid: string, publicKeyPem: string, envelope: array{payload: string, payloadType: string, signatures: list<array{keyid: string, sig: string}>}} */
        return json_decode((string) $json, true, flags: JSON_THROW_ON_ERROR);
    }

    /** The upstream scheme names: securesystemslib's, which go-securesystemslib shares. */
    private static function verifierFor(string $scheme, string $publicKeyPem): Verifier
    {
        return match ($scheme) {
            'ecdsa-sha2-nistp256' => EcdsaP256Verifier::fromPem($publicKeyPem),
            'ecdsa-sha2-nistp384' => EcdsaP384Verifier::fromPem($publicKeyPem),
            'ecdsa-sha2-nistp521' => EcdsaP521Verifier::fromPem($publicKeyPem),
            'ed25519' => PublicKey::fromPem($publicKeyPem),
            'rsassa-pss-sha256' => RsaPssVerifier::fromPem($publicKeyPem),
            'rsassa-pss-sha384' => RsaPssVerifier::fromPem($publicKeyPem, 'sha384'),
            'rsassa-pss-sha512' => RsaPssVerifier::fromPem($publicKeyPem, 'sha512'),
            'rsa-pkcs1v15-sha256' => RsaVerifier::fromPem($publicKeyPem),
            'rsa-pkcs1v15-sha384' => RsaVerifier::fromPem($publicKeyPem, 'sha384'),
            'rsa-pkcs1v15-sha512' => RsaVerifier::fromPem($publicKeyPem, 'sha512'),
            default => throw new RuntimeException('No verifier for scheme ' . $scheme),
        };
    }
}
