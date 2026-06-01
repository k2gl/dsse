<?php

declare(strict_types=1);

namespace K2gl\Dsse\Tests;

use K2gl\Dsse\EcdsaP256Signer;
use K2gl\Dsse\EcdsaP256Verifier;
use K2gl\Dsse\Envelope;
use K2gl\Dsse\Exception\CryptoException;
use K2gl\Dsse\Exception\SignatureVerificationFailed;
use K2gl\Dsse\Internal\Asn1EcdsaSignature;
use K2gl\Dsse\Pae;
use K2gl\Dsse\Signature;

use function K2gl\PHPUnitFluentAssertions\fact;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(EcdsaP256Signer::class)]
#[CoversClass(EcdsaP256Verifier::class)]
#[CoversClass(Asn1EcdsaSignature::class)]
#[CoversClass(Envelope::class)]
#[CoversClass(Signature::class)]
#[CoversClass(Pae::class)]
#[CoversClass(CryptoException::class)]
final class EcdsaP256Test extends TestCase
{
    public function testSignAndVerifyRoundTripWithRawSignature(): void
    {
        [$privatePem, $publicPem] = $this->generateKeyPair();
        $signer = EcdsaP256Signer::fromPem($privatePem, 'k1');
        $verifier = EcdsaP256Verifier::fromPem($publicPem);

        $envelope = Envelope::sign('the payload', 'application/vnd.test+json', $signer);

        fact($envelope->verify($verifier))->is('the payload');
        // Raw r||s encoding for P-256 is exactly 64 bytes (DER would be variable-length).
        fact(strlen($envelope->signatures[0]->sig))->is(64);
    }

    public function testVerifiesNativeDerSignature(): void
    {
        [$privatePem, $publicPem] = $this->generateKeyPair();
        $verifier = EcdsaP256Verifier::fromPem($publicPem);

        $privateKey = openssl_pkey_get_private($privatePem);
        fact($privateKey)->notFalse();
        // openssl_sign emits ASN.1 DER natively, the same encoding Sigstore carries.
        $der = '';
        fact(openssl_sign('the PAE bytes', $der, $privateKey, OPENSSL_ALGO_SHA256))->notFalse();

        fact($verifier->verify('the PAE bytes', $der))->true();
        fact($verifier->verify('other bytes', $der))->false();
    }

    public function testVerifiesDsseEnvelopeWithDerSignature(): void
    {
        [$privatePem, $publicPem] = $this->generateKeyPair();
        $verifier = EcdsaP256Verifier::fromPem($publicPem);

        $payload = 'the payload';
        $payloadType = 'application/vnd.test+json';

        $privateKey = openssl_pkey_get_private($privatePem);
        fact($privateKey)->notFalse();
        $der = '';
        fact(openssl_sign(Pae::encode($payloadType, $payload), $der, $privateKey, OPENSSL_ALGO_SHA256))->notFalse();

        $envelope = new Envelope($payload, $payloadType, [new Signature($der, null)]);

        fact($envelope->verify($verifier))->is($payload);
    }

    public function testTamperedPayloadDoesNotVerify(): void
    {
        [$privatePem, $publicPem] = $this->generateKeyPair();
        $signer = EcdsaP256Signer::fromPem($privatePem);
        $verifier = EcdsaP256Verifier::fromPem($publicPem);

        $envelope = Envelope::sign('the payload', 'application/vnd.test+json', $signer);
        $tampered = new Envelope('the PAYLOAD', $envelope->payloadType, $envelope->signatures);

        $this->expectException(SignatureVerificationFailed::class);
        $tampered->verify($verifier);
    }

    public function testRejectsInvalidPrivateKey(): void
    {
        $this->expectException(CryptoException::class);
        EcdsaP256Signer::fromPem('not a valid pem');
    }

    /** @return array{0: string, 1: string} */
    private function generateKeyPair(): array
    {
        $key = openssl_pkey_new([
            'private_key_type' => OPENSSL_KEYTYPE_EC,
            'curve_name' => 'prime256v1',
        ]);
        fact($key)->notFalse();
        openssl_pkey_export($key, $privatePem);
        $details = openssl_pkey_get_details($key);
        fact($details)->notFalse();

        return [(string) $privatePem, (string) $details['key']];
    }
}
