# Changelog

## 1.1.0

- **`EcdsaP256Verifier` now accepts ASN.1 DER signatures** in addition to raw
  `r||s`, detecting the encoding automatically. DSSE envelopes whose ECDSA P-256
  signatures are DER — the form OpenSSL emits and Sigstore bundles carry — now
  verify out of the box, with no custom verifier. Backward compatible: raw `r||s`
  signatures keep verifying exactly as before.

## 1.0.0

First public release. A faithful, zero-dependency implementation of DSSE
(Dead Simple Signing Envelope):

- **`Pae::encode()`** — Pre-Authentication Encoding, the exact byte string that is
  signed and verified; covered by the official spec test vector and binary-safe.
- **`Envelope`** — immutable value object with lossless `fromJson()` / `toJson()`
  and `sign()` / `verify()` helpers. Every error implements `DsseException`.
- **`Signer` / `Verifier`** — minimal interfaces so any key, KMS or HSM can be
  plugged in. Bundled implementations: `EcdsaP256Signer` / `EcdsaP256Verifier`
  (ECDSA P-256, raw `r||s` signatures, `ext-openssl`) and `Ed25519Signer` /
  `Ed25519Verifier` (`ext-sodium`).

Cross-implementation interop vectors (verifying envelopes produced by the Go and
Python reference signers) are planned for a follow-up release.
