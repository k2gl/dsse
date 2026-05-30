<?php

declare(strict_types=1);

namespace K2gl\Dsse;

/**
 * Verifies a raw signature against a PAE message for a single public key.
 */
interface Verifier
{
    public function verify(string $message, string $signature): bool;
}
