# k2gl/dsse

[![CI](https://img.shields.io/github/actions/workflow/status/k2gl/dsse/ci.yml?branch=main&label=CI&logo=github)](https://github.com/k2gl/dsse/actions/workflows/ci.yml)
[![Latest Stable Version](https://img.shields.io/packagist/v/k2gl/dsse?logo=packagist&logoColor=white)](https://packagist.org/packages/k2gl/dsse)
[![Total Downloads](https://img.shields.io/packagist/dt/k2gl/dsse?logo=packagist&logoColor=white)](https://packagist.org/packages/k2gl/dsse)
[![PHPStan Level](https://img.shields.io/badge/PHPStan-level%209-2a5ea7?logo=php&logoColor=white)](https://phpstan.org)
[![License](https://img.shields.io/packagist/l/k2gl/dsse?color=yellowgreen)](https://packagist.org/packages/k2gl/dsse)

Sign and verify DSSE (Dead Simple Signing Envelope) payloads in PHP with pluggable keys.
It's the envelope Sigstore, in-toto, SLSA and npm provenance use to wrap a signed payload.

It gives you the three pieces of the spec and nothing else:

- **PAE** — the exact, binary-safe byte string that gets signed.
- **Envelope** — the JSON envelope (`payload` / `payloadType` / `signatures`) with
  lossless (de)serialization.
- **Signer / Verifier** — tiny interfaces so you can plug in any key (or a remote
  KMS/HSM). ECDSA (P-256/384/521), Ed25519, and RSA (PKCS#1 v1.5) implementations are included.

## Install

```bash
composer require k2gl/dsse
```

Requires PHP 8.1+. The bundled signers use `ext-openssl` (ECDSA P-256/384/521, RSA) and
`ext-sodium` (Ed25519); both ship with PHP by default. The core (`Pae`, `Envelope`)
needs neither.

## Usage

### PAE — what actually gets signed

```php
use K2gl\Dsse\Pae;

Pae::encode('http://example.com/HelloWorld', 'hello world');
// "DSSEv1 29 http://example.com/HelloWorld 11 hello world"
```

Lengths are **byte** counts, so the encoding is unambiguous for any payload,
including binary data.

### Sign

```php
use K2gl\Dsse\Envelope;
use K2gl\Dsse\EcdsaP256Signer;

$signer   = EcdsaP256Signer::fromPem($privateKeyPem, keyId: 'k1');
$envelope = Envelope::sign('hello world', 'http://example.com/HelloWorld', $signer);

echo $envelope->toJson();
// {"payload":"aGVsbG8gd29ybGQ=","payloadType":"http://example.com/HelloWorld","signatures":[{"keyid":"k1","sig":"..."}]}
```

`Envelope::sign()` accepts several signers to produce a multi-signature envelope.

### Verify

```php
use K2gl\Dsse\Envelope;
use K2gl\Dsse\EcdsaP256Verifier;
use K2gl\Dsse\Exception\SignatureVerificationFailed;

$envelope = Envelope::fromJson($json);

try {
    $payload = $envelope->verify(EcdsaP256Verifier::fromPem($publicKeyPem));
    // $payload === 'hello world'
} catch (SignatureVerificationFailed) {
    // no signature matched any supplied verifier
}
```

The envelope is accepted if **any** signature verifies against **any** verifier you
pass, mirroring the spec's verification model. Pass several verifiers to accept a set
of trusted keys.

### Ed25519

```php
use K2gl\Dsse\Ed25519Signer;
use K2gl\Dsse\Ed25519Verifier;

$keypair  = sodium_crypto_sign_keypair();
$signer   = new Ed25519Signer(sodium_crypto_sign_secretkey($keypair), 'ed-1');
$verifier = new Ed25519Verifier(sodium_crypto_sign_publickey($keypair));
```

### ECDSA P-384 / P-521 and RSA

The other bundled algorithms follow the same `fromPem()` pattern:

```php
use K2gl\Dsse\EcdsaP384Signer;
use K2gl\Dsse\EcdsaP384Verifier;
use K2gl\Dsse\RsaSigner;
use K2gl\Dsse\RsaVerifier;

$signer   = EcdsaP384Signer::fromPem($p384PrivateKeyPem);
$verifier = EcdsaP384Verifier::fromPem($p384PublicKeyPem);

// RSASSA-PKCS1-v1_5; hash algorithm defaults to sha256 (sha384/sha512 also supported)
$rsaSigner   = RsaSigner::fromPem($rsaPrivateKeyPem, hashAlgorithm: 'sha512');
$rsaVerifier = RsaVerifier::fromPem($rsaPublicKeyPem, hashAlgorithm: 'sha512');
```

`EcdsaP521Signer` / `EcdsaP521Verifier` work identically.

### Plugging in your own key backend

Implement two methods to sign with a KMS/HSM or any other scheme:

```php
use K2gl\Dsse\Signer;

final class KmsSigner implements Signer
{
    public function sign(string $message): string { /* sign PAE bytes, return raw signature */ }
    public function keyId(): ?string { return 'arn:aws:kms:...'; }
}
```

## Design

- **Crypto-agnostic core.** `Pae` and `Envelope` carry no cryptography; signing is
  delegated to `Signer` / `Verifier`, so you control the algorithm and key storage.
- **Raw signatures.** The bundled ECDSA signers emit raw `r||s` signatures (64/96/132 bytes for P-256/384/521)
  (the form DSSE/JOSE/WebCrypto/Sigstore use), converting to and from OpenSSL's DER
  internally. The verifier accepts both raw `r||s` and ASN.1 DER signatures,
  detecting the encoding automatically — so DER signatures (OpenSSL native, Sigstore
  bundles) verify without any extra wiring.
- **Strict and typed.** `declare(strict_types=1)` throughout, analysed at PHPStan
  level 9; every exception implements `DsseException`.

## License

MIT — see [LICENSE](LICENSE).

Based on the DSSE specification (Apache-2.0) by the Secure Systems Lab; this is an
independent, clean-room PHP implementation.
