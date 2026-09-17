# Changelog

## 1.4.0

- **Cross-implementation vectors.** Envelopes signed by go-securesystemslib and by
  securesystemslib (Python) — ECDSA P-256/384/521, Ed25519, RSASSA-PSS, and PKCS#1 v1.5
  from Python — are verified in the test suite, and CI regenerates them with the upstream
  code and has Go and Python verify envelopes from every bundled signer in return. The
  follow-up promised in 1.0.0.
- **RSASSA-PSS**: `RsaPssSigner` / `RsaPssVerifier` (SHA-256/384/512, MGF1, salt as long
  as the hash), the RSA scheme both reference implementations use. ext-openssl has no PSS
  padding, so the RSA primitive is run bare and EMSA-PSS is done in PHP — still no
  dependencies.
- **DER output for ECDSA signers**: `SignatureEncoding::Der` on `fromPem()`, because the
  reference implementations verify DER only. Raw `r||s` stays the default; the verifiers
  keep accepting both.
- `PublicKey::fromJwk()` honours an RSA JWK's `alg`: `RS384`/`RS512` pick the hash,
  `PS256`/`PS384`/`PS512` pick PSS; an `alg` that is not a signature algorithm is refused.

## 1.3.0

- Add `PublicKey::fromPem()` and `PublicKey::fromJwk()` — load a public key and get the
  matching `Verifier` back, with the algorithm and curve detected automatically (RSA,
  ECDSA P-256/384/521, Ed25519). Useful for keys from a PEM file or a JWKS endpoint,
  where the type isn't known up front. RSA defaults to SHA-256.
- Add `KeyId::sha256Spki()` (hex SHA-256 of the DER public key — the cosign/Sigstore
  fingerprint) and `KeyId::jwkThumbprint()` (RFC 7638), for the `Signature` keyId field.
- No new dependencies — the loader uses `ext-openssl` and `ext-sodium`, like the existing
  signers.

## 1.2.0

- Add more signature algorithms alongside ECDSA P-256 and Ed25519:
  `EcdsaP384Signer`/`EcdsaP384Verifier` and `EcdsaP521Signer`/`EcdsaP521Verifier`
  (raw `r||s`, with automatic ASN.1 DER acceptance), plus `RsaSigner`/`RsaVerifier`
  (RSASSA-PKCS1-v1_5 over SHA-256/384/512). No new dependencies — the new signers
  use `ext-openssl`, like the existing ECDSA one.

## 1.1.1

- DER length decoding is now static-analysis clean on PHP 8.5 — no behaviour
  change.
- Development tooling (`pint.json`) is excluded from the distribution archive.
- Release tarballs are now published as GitHub release assets together with
  their Sigstore attestation bundle, signed via GitHub Artifact Attestations.

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
