<?php

declare(strict_types=1);

/*
 * Signs the interop payload with every bundled signer, one fixture per scheme,
 * for the Go and Python reference implementations to verify:
 *
 *   php tests/interop/php/generate.php <outDir>
 *
 * ECDSA signatures are written as DER — the encoding those implementations
 * verify. Scheme names are securesystemslib's.
 */

use K2gl\Dsse\EcdsaP256Signer;
use K2gl\Dsse\EcdsaP384Signer;
use K2gl\Dsse\EcdsaP521Signer;
use K2gl\Dsse\Ed25519Signer;
use K2gl\Dsse\Envelope;
use K2gl\Dsse\KeyId;
use K2gl\Dsse\RsaPssSigner;
use K2gl\Dsse\RsaSigner;
use K2gl\Dsse\SignatureEncoding;

require __DIR__ . '/../../../vendor/autoload.php';

$outDir = $argv[1] ?? null;

if (! is_string($outDir)) {
    fwrite(STDERR, "usage: generate.php <outDir>\n");
    exit(2);
}
$keysDir = __DIR__ . '/../keys';
$payloadType = 'application/vnd.in-toto+json';
$payload = '{"_type":"https://in-toto.io/Statement/v1","subject":[{"name":"artifact.tar.gz","digest":'
    . '{"sha256":"3f5a2d1e6c7b8a9f0e1d2c3b4a5968778695a4b3c2d1e0f9a8b7c6d5e4f3a2b1"}}],'
    . '"predicateType":"https://k2gl.com/dsse-interop/v1","predicate":{"note":"cross-implementation vector"}}';

$pem = static fn (string $name): string => (string) file_get_contents($keysDir . '/' . $name);
$ed25519Seed = static function (string $privatePem): string {
    // A PKCS#8 Ed25519 private key is a fixed 16-byte header followed by the 32-byte seed.
    $der = (string) base64_decode((string) preg_replace('/-----[^-]+-----|\s+/', '', $privatePem), true);

    return substr($der, -32);
};

$signers = [
    'ecdsa-sha2-nistp256' => ['ecdsa-p256', EcdsaP256Signer::fromPem($pem('ecdsa-p256.key.pem'), KeyId::sha256Spki($pem('ecdsa-p256.pub.pem')), SignatureEncoding::Der)],
    'ecdsa-sha2-nistp384' => ['ecdsa-p384', EcdsaP384Signer::fromPem($pem('ecdsa-p384.key.pem'), KeyId::sha256Spki($pem('ecdsa-p384.pub.pem')), SignatureEncoding::Der)],
    'ecdsa-sha2-nistp521' => ['ecdsa-p521', EcdsaP521Signer::fromPem($pem('ecdsa-p521.key.pem'), KeyId::sha256Spki($pem('ecdsa-p521.pub.pem')), SignatureEncoding::Der)],
    'ed25519' => ['ed25519', new Ed25519Signer(sodium_crypto_sign_secretkey(sodium_crypto_sign_seed_keypair($ed25519Seed($pem('ed25519.key.pem')))), KeyId::sha256Spki($pem('ed25519.pub.pem')))],
    'rsassa-pss-sha256' => ['rsa-2048', RsaPssSigner::fromPem($pem('rsa-2048.key.pem'), KeyId::sha256Spki($pem('rsa-2048.pub.pem')))],
    'rsa-pkcs1v15-sha256' => ['rsa-2048', RsaSigner::fromPem($pem('rsa-2048.key.pem'), KeyId::sha256Spki($pem('rsa-2048.pub.pem')))],
];

if (! is_dir($outDir) && ! mkdir($outDir, 0755, true)) {
    fwrite(STDERR, "cannot create {$outDir}\n");
    exit(1);
}
$version = json_decode((string) file_get_contents(__DIR__ . '/../../../composer.json'), true, flags: JSON_THROW_ON_ERROR)['name'];

foreach ($signers as $scheme => [$key, $signer]) {
    $envelope = Envelope::sign($payload, $payloadType, $signer);
    $fixture = [
        'implementation' => 'k2gl/dsse',
        'version' => 'working tree',
        'scheme' => $scheme,
        'keyid' => $signer->keyId(),
        'publicKeyPem' => $pem($key . '.pub.pem'),
        'envelope' => $envelope->toArray(),
    ];
    $name = $outDir . '/php-' . $scheme . '.json';
    file_put_contents($name, json_encode($fixture, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR) . "\n");
    echo "wrote {$name}\n";
}
