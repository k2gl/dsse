<?php

declare(strict_types=1);

namespace K2gl\Dsse;

/**
 * One signature over an {@see Envelope}'s PAE: the raw signature bytes plus an
 * optional key identifier hint. The key id may help a verifier pick a key, but
 * it is never trusted on its own.
 */
final class Signature
{
    public function __construct(
        public readonly string $sig,
        public readonly ?string $keyId = null,
    ) {
    }
}
