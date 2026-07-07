<?php

declare(strict_types=1);

namespace K2gl\Dsse\Tests;

use K2gl\Dsse\Envelope;
use K2gl\Dsse\Exception\CryptoException;
use K2gl\Dsse\Exception\SignatureVerificationFailed;
use K2gl\Dsse\RsaSigner;
use K2gl\Dsse\RsaVerifier;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

use function K2gl\PHPUnitFluentAssertions\fact;

#[CoversClass(RsaSigner::class)]
#[CoversClass(RsaVerifier::class)]
final class RsaTest extends TestCase
{
    public function testSignAndVerifyRoundTrip(): void
    {
        [$privatePem, $publicPem] = $this->generateKeyPair();
        $envelope = Envelope::sign('the payload', 'application/vnd.test+json', RsaSigner::fromPem($privatePem, 'k1'));

        fact($envelope->verify(RsaVerifier::fromPem($publicPem)))->is('the payload');
    }

    public function testRoundTripWithSha512(): void
    {
        [$privatePem, $publicPem] = $this->generateKeyPair();
        $signer = RsaSigner::fromPem($privatePem, null, 'sha512');

        $envelope = Envelope::sign('the payload', 'application/vnd.test+json', $signer);

        fact($envelope->verify(RsaVerifier::fromPem($publicPem, 'sha512')))->is('the payload');
    }

    public function testHashAlgorithmMismatchDoesNotVerify(): void
    {
        // arrange
        [$privatePem, $publicPem] = $this->generateKeyPair();
        $envelope = Envelope::sign('the payload', 'application/vnd.test+json', RsaSigner::fromPem($privatePem, null, 'sha256'));

        // Verifier configured for a different hash must reject.
        // act + assert
        fact(static fn () => $envelope->verify(RsaVerifier::fromPem($publicPem, 'sha512')))
            ->throws(SignatureVerificationFailed::class);
    }

    public function testTamperedPayloadDoesNotVerify(): void
    {
        // arrange
        [$privatePem, $publicPem] = $this->generateKeyPair();
        $envelope = Envelope::sign('the payload', 'application/vnd.test+json', RsaSigner::fromPem($privatePem));
        $tampered = new Envelope('the PAYLOAD', $envelope->payloadType, $envelope->signatures);

        // act + assert
        fact(static fn () => $tampered->verify(RsaVerifier::fromPem($publicPem)))->throws(SignatureVerificationFailed::class);
    }

    public function testRejectsUnsupportedHashAlgorithm(): void
    {
        // arrange
        [$privatePem] = $this->generateKeyPair();

        // act + assert
        fact(static fn () => RsaSigner::fromPem($privatePem, null, 'md5'))->throws(CryptoException::class);
    }

    public function testRejectsInvalidPrivateKey(): void
    {
        // act + assert
        fact(static fn () => RsaSigner::fromPem('not a valid pem'))->throws(CryptoException::class);
    }

    /** @return array{0: string, 1: string} */
    private function generateKeyPair(): array
    {
        $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
        fact($key)->notFalse();
        openssl_pkey_export($key, $privatePem);
        $details = openssl_pkey_get_details($key);
        fact($details)->notFalse();

        return [(string) $privatePem, (string) $details['key']];
    }
}
