<?php

declare(strict_types=1);

namespace K2gl\Dsse;

/**
 * Produces a signature over a PAE message. Implementations wrap a concrete
 * algorithm and key (or a remote KMS/HSM). The package ships ECDSA P-256 and
 * Ed25519 defaults.
 */
interface Signer
{
    /** Sign the given PAE bytes and return the raw signature bytes. */
    public function sign(string $message): string;

    /** Optional key identifier recorded alongside the signature. */
    public function keyId(): ?string;
}
