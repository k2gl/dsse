<?php

declare(strict_types=1);

namespace K2gl\Dsse\Tests;

use K2gl\Dsse\EcdsaP384Signer;
use K2gl\Dsse\EcdsaP384Verifier;
use K2gl\Dsse\Envelope;
use K2gl\Dsse\Exception\CryptoException;
use K2gl\Dsse\Exception\SignatureVerificationFailed;
use K2gl\Dsse\Internal\Asn1EcdsaSignature;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

use function K2gl\PHPUnitFluentAssertions\fact;

#[CoversClass(EcdsaP384Signer::class)]
#[CoversClass(EcdsaP384Verifier::class)]
#[CoversClass(Asn1EcdsaSignature::class)]
final class EcdsaP384Test extends TestCase
{
    public function testSignAndVerifyRoundTripWithRawSignature(): void
    {
        [$privatePem, $publicPem] = $this->generateKeyPair();
        $envelope = Envelope::sign('the payload', 'application/vnd.test+json', EcdsaP384Signer::fromPem($privatePem, 'k1'));

        fact($envelope->verify(EcdsaP384Verifier::fromPem($publicPem)))->is('the payload');
        // Raw r||s for P-384 is exactly 96 bytes.
        fact(strlen($envelope->signatures[0]->sig))->is(96);
    }

    public function testVerifiesNativeDerSignature(): void
    {
        [$privatePem, $publicPem] = $this->generateKeyPair();
        $verifier = EcdsaP384Verifier::fromPem($publicPem);

        $privateKey = openssl_pkey_get_private($privatePem);
        fact($privateKey)->notFalse();
        $der = '';
        fact(openssl_sign('the PAE bytes', $der, $privateKey, OPENSSL_ALGO_SHA384))->notFalse();

        fact($verifier->verify('the PAE bytes', $der))->true();
        fact($verifier->verify('other bytes', $der))->false();
    }

    public function testTamperedPayloadDoesNotVerify(): void
    {
        [$privatePem, $publicPem] = $this->generateKeyPair();
        $envelope = Envelope::sign('the payload', 'application/vnd.test+json', EcdsaP384Signer::fromPem($privatePem));
        $tampered = new Envelope('the PAYLOAD', $envelope->payloadType, $envelope->signatures);

        $this->expectException(SignatureVerificationFailed::class);
        $tampered->verify(EcdsaP384Verifier::fromPem($publicPem));
    }

    public function testRejectsInvalidPrivateKey(): void
    {
        $this->expectException(CryptoException::class);
        EcdsaP384Signer::fromPem('not a valid pem');
    }

    /** @return array{0: string, 1: string} */
    private function generateKeyPair(): array
    {
        $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'secp384r1']);
        fact($key)->notFalse();
        openssl_pkey_export($key, $privatePem);
        $details = openssl_pkey_get_details($key);
        fact($details)->notFalse();

        return [(string) $privatePem, (string) $details['key']];
    }
}
