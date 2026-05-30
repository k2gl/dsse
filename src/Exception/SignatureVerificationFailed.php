<?php

declare(strict_types=1);

namespace K2gl\Dsse\Exception;

/**
 * Thrown when none of an envelope's signatures can be verified against the
 * supplied verifiers.
 */
final class SignatureVerificationFailed extends \RuntimeException implements DsseException
{
}
