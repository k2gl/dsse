<?php

declare(strict_types=1);

namespace K2gl\Dsse\Tests;

use K2gl\Dsse\Envelope;
use K2gl\Dsse\Exception\CryptoException;
use K2gl\Dsse\Exception\SignatureVerificationFailed;
use K2gl\Dsse\Internal\Pss;
use K2gl\Dsse\RsaPssSigner;
use K2gl\Dsse\RsaPssVerifier;
use K2gl\Dsse\RsaSigner;
use K2gl\Dsse\RsaVerifier;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\TestWith;
use PHPUnit\Framework\TestCase;

use function K2gl\PHPUnitFluentAssertions\fact;

#[CoversClass(RsaPssSigner::class)]
#[CoversClass(RsaPssVerifier::class)]
#[CoversClass(Pss::class)]
final class RsaPssTest extends TestCase
{
    #[TestWith(['sha256'])]
    #[TestWith(['sha384'])]
    #[TestWith(['sha512'])]
    public function testSignAndVerifyRoundTrip(string $hash): void
    {
        [$privatePem, $publicPem] = self::keyPair();
        $envelope = Envelope::sign('the payload', 'application/vnd.test+json', RsaPssSigner::fromPem($privatePem, 'k1', $hash));

        fact($envelope->signatures[0]->keyId)->is('k1');
        fact($envelope->signatures[0]->sig)->hasLength(256);
        fact($envelope->verify(RsaPssVerifier::fromPem($publicPem, $hash)))->is('the payload');
    }

    public function testEverySignatureIsSaltedDifferently(): void
    {
        [$privatePem, $publicPem] = self::keyPair();
        $signer = RsaPssSigner::fromPem($privatePem);

        $first = $signer->sign('same message');
        $second = $signer->sign('same message');

        fact($first)->not($second);
        fact(RsaPssVerifier::fromPem($publicPem)->verify('same message', $first))->true();
        fact(RsaPssVerifier::fromPem($publicPem)->verify('same message', $second))->true();
    }

    public function testRejectsATamperedMessageAndSignature(): void
    {
        [$privatePem, $publicPem] = self::keyPair();
        $signature = RsaPssSigner::fromPem($privatePem)->sign('the message');
        $verifier = RsaPssVerifier::fromPem($publicPem);
        $flipped = $signature;
        $flipped[100] = chr(ord($flipped[100]) ^ 0x01);

        fact($verifier->verify('tampered', $signature))->false();
        fact($verifier->verify('the message', $flipped))->false();
        fact($verifier->verify('the message', substr($signature, 1)))->false();
        fact($verifier->verify('the message', ''))->false();
    }

    public function testRejectsAnotherKey(): void
    {
        [$privatePem] = self::keyPair();
        [, $otherPublicPem] = self::keyPair();
        $signature = RsaPssSigner::fromPem($privatePem)->sign('the message');

        fact(RsaPssVerifier::fromPem($otherPublicPem)->verify('the message', $signature))->false();
    }

    public function testPssAndPkcs1DoNotVerifyEachOther(): void
    {
        [$privatePem, $publicPem] = self::keyPair();
        $pss = RsaPssSigner::fromPem($privatePem)->sign('the message');
        $pkcs1 = RsaSigner::fromPem($privatePem)->sign('the message');

        fact(RsaVerifier::fromPem($publicPem)->verify('the message', $pss))->false();
        fact(RsaPssVerifier::fromPem($publicPem)->verify('the message', $pkcs1))->false();
    }

    public function testHashAlgorithmMismatchDoesNotVerify(): void
    {
        // arrange
        [$privatePem, $publicPem] = self::keyPair();
        $envelope = Envelope::sign('p', 't', RsaPssSigner::fromPem($privatePem, null, 'sha384'));

        // act + assert
        fact(static fn () => $envelope->verify(RsaPssVerifier::fromPem($publicPem, 'sha256')))
            ->throws(SignatureVerificationFailed::class);
    }

    public function testRejectsUnsupportedHashAndNonRsaKeys(): void
    {
        // arrange
        [$privatePem, $publicPem] = self::keyPair();
        $ec = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
        fact($ec)->notFalse();
        openssl_pkey_export($ec, $ecPrivatePem);
        $ecPublicPem = (string) openssl_pkey_get_details($ec)['key'];

        // act + assert
        fact(static fn () => RsaPssSigner::fromPem($privatePem, null, 'md5'))->throws(CryptoException::class);
        fact(static fn () => RsaPssVerifier::fromPem($publicPem, 'sha1'))->throws(CryptoException::class);
        fact(static fn () => RsaPssSigner::fromPem((string) $ecPrivatePem))->throws(CryptoException::class);
        fact(static fn () => RsaPssVerifier::fromPem($ecPublicPem))->throws(CryptoException::class);
        fact(static fn () => RsaPssSigner::fromPem('not a pem'))->throws(CryptoException::class);
        fact(static fn () => RsaPssVerifier::fromPem('not a pem'))->throws(CryptoException::class);
    }

    public function testRefusesAKeyTooSmallForTheHash(): void
    {
        // arrange — 512 bits leave no room for SHA-512 hash + salt + padding
        $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 512]);
        fact($key)->notFalse();
        openssl_pkey_export($key, $privatePem);
        $signer = RsaPssSigner::fromPem((string) $privatePem, null, 'sha512');

        // act + assert
        fact(static fn () => $signer->sign('m'))->throws(CryptoException::class);
    }

    /** @return array{0: string, 1: string} */
    private static function keyPair(): array
    {
        $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
        fact($key)->notFalse();
        openssl_pkey_export($key, $privatePem);
        $details = openssl_pkey_get_details($key);
        fact($details)->notFalse();

        return [(string) $privatePem, (string) $details['key']];
    }
}
