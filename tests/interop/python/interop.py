#!/usr/bin/env python3
"""Interop with securesystemslib, the Python reference implementation of DSSE.

    python interop.py generate <keysDir> <outDir>   sign the interop payload with every key, one fixture per scheme
    python interop.py verify <dir>                  verify every fixture in the directory with securesystemslib

A fixture is a JSON object: implementation, version, scheme, keyid, publicKeyPem, envelope.
"""

import json
import pathlib
import sys

import securesystemslib
from cryptography.hazmat.primitives import serialization
from securesystemslib.dsse import Envelope
from securesystemslib.signer import CryptoSigner, SSlibKey

PAYLOAD_TYPE = "application/vnd.in-toto+json"
PAYLOAD = (
    '{"_type":"https://in-toto.io/Statement/v1","subject":[{"name":"artifact.tar.gz","digest":'
    '{"sha256":"3f5a2d1e6c7b8a9f0e1d2c3b4a5968778695a4b3c2d1e0f9a8b7c6d5e4f3a2b1"}}],'
    '"predicateType":"https://k2gl.com/dsse-interop/v1","predicate":{"note":"cross-implementation vector"}}'
).encode()

# The keys under tests/interop/keys and the schemes each signs with. RSA signs
# both ways: PSS is securesystemslib's default, PKCS#1 v1.5 its other scheme.
KEYS = [
    ("ecdsa-p256.key.pem", ["ecdsa-sha2-nistp256"]),
    ("ecdsa-p384.key.pem", ["ecdsa-sha2-nistp384"]),
    ("ecdsa-p521.key.pem", ["ecdsa-sha2-nistp521"]),
    ("ed25519.key.pem", ["ed25519"]),
    ("rsa-2048.key.pem", ["rsassa-pss-sha256", "rsa-pkcs1v15-sha256"]),
]


def generate(keys_dir: pathlib.Path, out_dir: pathlib.Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    for file, schemes in KEYS:
        private = serialization.load_pem_private_key((keys_dir / file).read_bytes(), password=None)
        public_pem = (keys_dir / file.replace(".key.pem", ".pub.pem")).read_text()
        for scheme in schemes:
            key = SSlibKey.from_crypto(private.public_key(), scheme=scheme)
            envelope = Envelope(payload=PAYLOAD, payload_type=PAYLOAD_TYPE, signatures={})
            envelope.sign(CryptoSigner(private, key))
            fixture = {
                "implementation": "securesystemslib",
                "version": securesystemslib.__version__,
                "scheme": scheme,
                "keyid": key.keyid,
                "publicKeyPem": public_pem,
                "envelope": envelope.to_dict(),
            }
            name = out_dir / f"python-{scheme}.json"
            name.write_text(json.dumps(fixture, indent=2) + "\n")
            print("wrote", name)


def verify(directory: pathlib.Path) -> None:
    files = sorted(directory.glob("*.json"))
    if not files:
        sys.exit(f"no fixtures in {directory}")
    for file in files:
        fixture = json.loads(file.read_text())
        public = serialization.load_pem_public_key(fixture["publicKeyPem"].encode())
        # securesystemslib matches signatures to keys by key id, so take the envelope's.
        key = SSlibKey.from_crypto(public, keyid=fixture["keyid"], scheme=fixture["scheme"])
        Envelope.from_dict(fixture["envelope"]).verify([key], 1)  # raises when nothing verifies
        print("ok   ", file)


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "generate":
        generate(pathlib.Path(sys.argv[2]), pathlib.Path(sys.argv[3]))
    elif len(sys.argv) == 3 and sys.argv[1] == "verify":
        verify(pathlib.Path(sys.argv[2]))
    else:
        sys.exit(__doc__)
