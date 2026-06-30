<?php

declare(strict_types=1);

namespace K2gl\Dsse\Tests;

use K2gl\Dsse\EcdsaP521Signer;
use K2gl\Dsse\EcdsaP521Verifier;
use K2gl\Dsse\Envelope;
use K2gl\Dsse\Exception\CryptoException;
use K2gl\Dsse\Exception\SignatureVerificationFailed;
use K2gl\Dsse\Internal\Asn1EcdsaSignature;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

use function K2gl\PHPUnitFluentAssertions\fact;

#[CoversClass(EcdsaP521Signer::class)]
#[CoversClass(EcdsaP521Verifier::class)]
#[CoversClass(Asn1EcdsaSignature::class)]
final class EcdsaP521Test extends TestCase
{
    public function testSignAndVerifyRoundTripWithRawSignature(): void
    {
        [$privatePem, $publicPem] = $this->generateKeyPair();
        $envelope = Envelope::sign('the payload', 'application/vnd.test+json', EcdsaP521Signer::fromPem($privatePem, 'k1'));

        fact($envelope->verify(EcdsaP521Verifier::fromPem($publicPem)))->is('the payload');
        // Raw r||s for P-521 is exactly 132 bytes (66 per coordinate).
        fact(strlen($envelope->signatures[0]->sig))->is(132);
    }

    public function testVerifiesNativeDerSignature(): void
    {
        [$privatePem, $publicPem] = $this->generateKeyPair();
        $verifier = EcdsaP521Verifier::fromPem($publicPem);

        $privateKey = openssl_pkey_get_private($privatePem);
        fact($privateKey)->notFalse();
        $der = '';
        fact(openssl_sign('the PAE bytes', $der, $privateKey, OPENSSL_ALGO_SHA512))->notFalse();

        fact($verifier->verify('the PAE bytes', $der))->true();
        fact($verifier->verify('other bytes', $der))->false();
    }

    public function testTamperedPayloadDoesNotVerify(): void
    {
        [$privatePem, $publicPem] = $this->generateKeyPair();
        $envelope = Envelope::sign('the payload', 'application/vnd.test+json', EcdsaP521Signer::fromPem($privatePem));
        $tampered = new Envelope('the PAYLOAD', $envelope->payloadType, $envelope->signatures);

        $this->expectException(SignatureVerificationFailed::class);
        $tampered->verify(EcdsaP521Verifier::fromPem($publicPem));
    }

    public function testRejectsInvalidPrivateKey(): void
    {
        $this->expectException(CryptoException::class);
        EcdsaP521Signer::fromPem('not a valid pem');
    }

    /** @return array{0: string, 1: string} */
    private function generateKeyPair(): array
    {
        $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'secp521r1']);
        fact($key)->notFalse();
        openssl_pkey_export($key, $privatePem);
        $details = openssl_pkey_get_details($key);
        fact($details)->notFalse();

        return [(string) $privatePem, (string) $details['key']];
    }
}
