<?php

declare(strict_types=1);

namespace K2gl\Dsse\Exception;

use RuntimeException;

/**
 * Thrown when a cryptographic operation fails: a key cannot be loaded, signing
 * fails, or a signature is malformed.
 */
final class CryptoException extends RuntimeException implements DsseException {}
