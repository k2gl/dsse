<?php

declare(strict_types=1);

namespace K2gl\Dsse;

/**
 * How an ECDSA signer writes its signature. DSSE leaves the encoding to the
 * algorithm, and the two forms in circulation are the raw `r||s` concatenation
 * (JOSE, WebCrypto, the DSSE examples) and ASN.1 DER (OpenSSL's native form,
 * Sigstore bundles, and what the Go and Python reference implementations
 * verify). The bundled verifiers accept both.
 */
enum SignatureEncoding
{
    case Raw;
    case Der;
}
