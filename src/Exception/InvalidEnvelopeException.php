<?php

declare(strict_types=1);

namespace K2gl\Dsse\Exception;

use RuntimeException;

/**
 * Thrown when an envelope cannot be parsed: invalid JSON, missing or wrongly
 * typed fields, or values that are not valid base64.
 */
final class InvalidEnvelopeException extends RuntimeException implements DsseException {}
