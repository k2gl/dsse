<?php

declare(strict_types=1);

namespace K2gl\Dsse;

use K2gl\Dsse\Exception\InvalidEnvelopeException;
use K2gl\Dsse\Exception\SignatureVerificationFailed;
use InvalidArgumentException;
use JsonException;

/**
 * An immutable DSSE envelope: a payload, its type, and one or more signatures
 * over the payload's PAE. Provides lossless JSON (de)serialization and the
 * sign/verify operations defined by the DSSE protocol.
 *
 * @see https://github.com/secure-systems-lab/dsse/blob/master/envelope.md
 */
final class Envelope
{
    /** @param list<Signature> $signatures */
    public function __construct(
        public readonly string $payload,
        public readonly string $payloadType,
        public readonly array $signatures,
    ) {}

    /** The exact bytes that are signed and verified for this envelope. */
    public function pae(): string
    {
        return Pae::encode($this->payloadType, $this->payload);
    }

    /** Sign a payload with one or more signers and wrap the result in an envelope. */
    public static function sign(string $payload, string $payloadType, Signer ...$signers): self
    {
        if ($signers === []) {
            throw new InvalidArgumentException('At least one signer is required.');
        }
        $pae = Pae::encode($payloadType, $payload);
        $signatures = [];

        foreach ($signers as $signer) {
            $signatures[] = new Signature($signer->sign($pae), $signer->keyId());
        }

        return new self($payload, $payloadType, $signatures);
    }

    /**
     * Accept the envelope if any of its signatures verifies against any of the
     * supplied verifiers, and return the decoded payload. Throws otherwise.
     */
    public function verify(Verifier ...$verifiers): string
    {
        if ($verifiers === []) {
            throw new InvalidArgumentException('At least one verifier is required.');
        }
        $pae = $this->pae();

        foreach ($this->signatures as $signature) {
            foreach ($verifiers as $verifier) {
                if ($verifier->verify($pae, $signature->sig)) {
                    return $this->payload;
                }
            }
        }
        throw new SignatureVerificationFailed('No signature could be verified against the supplied verifiers.');
    }

    /** Parse a DSSE JSON envelope. */
    public static function fromJson(string $json): self
    {
        try {
            /** @var mixed $data */
            $data = json_decode($json, true, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException $e) {
            throw new InvalidEnvelopeException('Envelope is not valid JSON: ' . $e->getMessage(), previous: $e);
        }

        if (! is_array($data)) {
            throw new InvalidEnvelopeException('Envelope must be a JSON object.');
        }

        return self::fromArray($data);
    }

    /** @param array<mixed> $data */
    public static function fromArray(array $data): self
    {
        $payload = self::decodeBase64($data['payload'] ?? null, 'payload');

        $payloadType = $data['payloadType'] ?? null;

        if (! is_string($payloadType) || $payloadType === '') {
            throw new InvalidEnvelopeException('Envelope is missing a non-empty "payloadType".');
        }

        $rawSignatures = $data['signatures'] ?? null;

        if (! is_array($rawSignatures) || $rawSignatures === []) {
            throw new InvalidEnvelopeException('Envelope must contain a non-empty "signatures" array.');
        }

        $signatures = [];

        foreach ($rawSignatures as $raw) {
            if (! is_array($raw)) {
                throw new InvalidEnvelopeException('Each signature must be a JSON object.');
            }
            $sig = self::decodeBase64($raw['sig'] ?? null, 'sig');
            $keyId = $raw['keyid'] ?? null;

            if ($keyId !== null && ! is_string($keyId)) {
                throw new InvalidEnvelopeException('Signature "keyid" must be a string.');
            }
            $signatures[] = new Signature($sig, $keyId);
        }

        return new self($payload, $payloadType, $signatures);
    }

    /** @return array{payload: string, payloadType: string, signatures: list<array<string, string>>} */
    public function toArray(): array
    {
        $signatures = [];

        foreach ($this->signatures as $signature) {
            $entry = [];

            if ($signature->keyId !== null) {
                $entry['keyid'] = $signature->keyId;
            }
            $entry['sig'] = base64_encode($signature->sig);
            $signatures[] = $entry;
        }

        return [
            'payload' => base64_encode($this->payload),
            'payloadType' => $this->payloadType,
            'signatures' => $signatures,
        ];
    }

    public function toJson(): string
    {
        return json_encode($this->toArray(), JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
    }

    private static function decodeBase64(mixed $value, string $field): string
    {
        if (! is_string($value)) {
            throw new InvalidEnvelopeException(sprintf('Envelope is missing a valid "%s".', $field));
        }
        $decoded = base64_decode($value, true);

        if ($decoded === false) {
            throw new InvalidEnvelopeException(sprintf('Envelope field "%s" is not valid base64.', $field));
        }

        return $decoded;
    }
}
