<?php

declare(strict_types=1);

namespace K2gl\Dsse\Tests;

use K2gl\Dsse\Ed25519Signer;
use K2gl\Dsse\Ed25519Verifier;
use K2gl\Dsse\Envelope;
use K2gl\Dsse\Exception\CryptoException;
use K2gl\Dsse\Exception\SignatureVerificationFailed;
use K2gl\Dsse\Pae;
use K2gl\Dsse\Signature;

use function K2gl\PHPUnitFluentAssertions\fact;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(Ed25519Signer::class)]
#[CoversClass(Ed25519Verifier::class)]
#[CoversClass(Envelope::class)]
#[CoversClass(Signature::class)]
#[CoversClass(Pae::class)]
#[CoversClass(CryptoException::class)]
final class Ed25519Test extends TestCase
{
    public function testSignAndVerifyRoundTrip(): void
    {
        $keypair = sodium_crypto_sign_keypair();
        $signer = new Ed25519Signer(sodium_crypto_sign_secretkey($keypair), 'ed-1');
        $verifier = new Ed25519Verifier(sodium_crypto_sign_publickey($keypair));

        $envelope = Envelope::sign('the payload', 'application/vnd.test+json', $signer);

        fact($envelope->verify($verifier))->is('the payload');
        fact($envelope->signatures[0]->keyId)->is('ed-1');
    }

    public function testTamperedPayloadDoesNotVerify(): void
    {
        $keypair = sodium_crypto_sign_keypair();
        $signer = new Ed25519Signer(sodium_crypto_sign_secretkey($keypair));
        $verifier = new Ed25519Verifier(sodium_crypto_sign_publickey($keypair));

        $envelope = Envelope::sign('the payload', 'application/vnd.test+json', $signer);
        $tampered = new Envelope('the PAYLOAD', $envelope->payloadType, $envelope->signatures);

        $this->expectException(SignatureVerificationFailed::class);
        $tampered->verify($verifier);
    }

    public function testRejectsWrongSizedKey(): void
    {
        $this->expectException(CryptoException::class);
        new Ed25519Signer('too short');
    }
}
