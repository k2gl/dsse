<?php

declare(strict_types=1);

namespace K2gl\Dsse\Tests;

use K2gl\Dsse\Envelope;
use K2gl\Dsse\Exception\InvalidEnvelopeException;
use K2gl\Dsse\Exception\SignatureVerificationFailed;
use K2gl\Dsse\Pae;
use K2gl\Dsse\Signature;
use K2gl\Dsse\Signer;
use K2gl\Dsse\Verifier;

use function K2gl\PHPUnitFluentAssertions\fact;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(Envelope::class)]
#[CoversClass(Signature::class)]
#[CoversClass(Pae::class)]
#[CoversClass(InvalidEnvelopeException::class)]
#[CoversClass(SignatureVerificationFailed::class)]
final class EnvelopeTest extends TestCase
{
    private const EXAMPLE_JSON = '{"payload":"aGVsbG8gd29ybGQ=","payloadType":"http://example.com/HelloWorld","signatures":[{"sig":"A3JqsQGtVsJ2O2xqrI5IcnXip5GToJ3F+FnZ+O88SjtR6rDAajabZKciJTfUiHqJPcIAriEGAHTVeCUjW2JIZA=="}]}';

    public function testParsesAndReEmitsTheOfficialExampleEnvelope(): void
    {
        $envelope = Envelope::fromJson(self::EXAMPLE_JSON);

        fact($envelope->payload)->is('hello world');
        fact($envelope->payloadType)->is('http://example.com/HelloWorld');
        fact(count($envelope->signatures))->is(1);
        fact($envelope->toJson())->is(self::EXAMPLE_JSON);
    }

    public function testSignThenVerifyReturnsPayload(): void
    {
        $envelope = Envelope::sign('hello world', 'http://example.com/HelloWorld', $this->fakeSigner('test-key'));

        fact($envelope->payloadType)->is('http://example.com/HelloWorld');
        fact($envelope->signatures[0]->keyId)->is('test-key');
        fact($envelope->verify($this->fakeVerifier()))->is('hello world');
    }

    public function testVerifyFailsWhenNoSignatureMatches(): void
    {
        $envelope = Envelope::sign('hello world', 'application/vnd.test', $this->fakeSigner(null));
        $rejecting = new class () implements Verifier {
            public function verify(string $message, string $signature): bool
            {
                return false;
            }
        };

        $this->expectException(SignatureVerificationFailed::class);
        $envelope->verify($rejecting);
    }

    public function testRejectsMalformedJson(): void
    {
        $this->expectException(InvalidEnvelopeException::class);
        Envelope::fromJson('{not json');
    }

    public function testRejectsMissingPayloadType(): void
    {
        $this->expectException(InvalidEnvelopeException::class);
        Envelope::fromJson('{"payload":"aGk=","signatures":[{"sig":"YQ=="}]}');
    }

    private function fakeSigner(?string $keyId): Signer
    {
        return new class ($keyId) implements Signer {
            public function __construct(private readonly ?string $keyId)
            {
            }

            public function sign(string $message): string
            {
                return 'sig:' . $message;
            }

            public function keyId(): ?string
            {
                return $this->keyId;
            }
        };
    }

    private function fakeVerifier(): Verifier
    {
        return new class () implements Verifier {
            public function verify(string $message, string $signature): bool
            {
                return $signature === 'sig:' . $message;
            }
        };
    }
}
