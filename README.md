# k2gl/dsse

A faithful, zero-dependency PHP implementation of **DSSE** — the
[Dead Simple Signing Envelope](https://github.com/secure-systems-lab/dsse) used by
Sigstore, in-toto, SLSA and npm provenance to sign and verify arbitrary payloads.

It gives you the three pieces of the spec and nothing else:

- **PAE** — the exact, binary-safe byte string that gets signed.
- **Envelope** — the JSON envelope (`payload` / `payloadType` / `signatures`) with
  lossless (de)serialization.
- **Signer / Verifier** — tiny interfaces so you can plug in any key (or a remote
  KMS/HSM). ECDSA P-256 and Ed25519 implementations are included.

## Install

```bash
composer require k2gl/dsse
```

Requires PHP 8.1+. The bundled signers use `ext-openssl` (ECDSA P-256) and
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
- **Raw signatures.** The bundled ECDSA P-256 signer emits 64-byte `r||s` signatures
  (the form DSSE/JOSE/WebCrypto/Sigstore use), converting to and from OpenSSL's DER
  internally.
- **Strict and typed.** `declare(strict_types=1)` throughout, analysed at PHPStan
  level 9; every exception implements `DsseException`.

## License

MIT — see [LICENSE](LICENSE).

Based on the DSSE specification (Apache-2.0) by the Secure Systems Lab; this is an
independent, clean-room PHP implementation.
