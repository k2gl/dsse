// Interop with go-securesystemslib, the Go reference implementation of DSSE.
//
//	go run . generate <keysDir> <outDir>   sign the interop payload with every key, one fixture per scheme
//	go run . verify <dir>                  verify every fixture in the directory with go-securesystemslib
//
// A fixture is a JSON object: implementation, version, scheme, keyid, publicKeyPem, envelope.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"

	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/secure-systems-lab/go-securesystemslib/signerverifier"
)

const payloadType = "application/vnd.in-toto+json"

const payload = `{"_type":"https://in-toto.io/Statement/v1","subject":[{"name":"artifact.tar.gz","digest":{"sha256":"3f5a2d1e6c7b8a9f0e1d2c3b4a5968778695a4b3c2d1e0f9a8b7c6d5e4f3a2b1"}}],"predicateType":"https://k2gl.com/dsse-interop/v1","predicate":{"note":"cross-implementation vector"}}`

type fixture struct {
	Implementation string         `json:"implementation"`
	Version        string         `json:"version"`
	Scheme         string         `json:"scheme"`
	KeyID          string         `json:"keyid"`
	PublicKeyPem   string         `json:"publicKeyPem"`
	Envelope       *dsse.Envelope `json:"envelope"`
}

// The keys under tests/interop/keys and the scheme each signs with. RSA is
// PSS only: that is the one RSA scheme go-securesystemslib implements.
var keys = []struct{ file, scheme string }{
	{"ecdsa-p256.key.pem", "ecdsa-sha2-nistp256"},
	{"ecdsa-p384.key.pem", "ecdsa-sha2-nistp384"},
	{"ecdsa-p521.key.pem", "ecdsa-sha2-nistp521"},
	{"ed25519.key.pem", "ed25519"},
	{"rsa-2048.key.pem", "rsassa-pss-sha256"},
}

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: generate <keysDir> <outDir> | verify <dir>")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "generate":
		if len(os.Args) != 4 {
			fmt.Fprintln(os.Stderr, "usage: generate <keysDir> <outDir>")
			os.Exit(2)
		}
		err = generate(os.Args[2], os.Args[3])
	case "verify":
		err = verify(os.Args[2])
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func generate(keysDir, outDir string) error {
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}
	for _, k := range keys {
		pem, err := os.ReadFile(filepath.Join(keysDir, k.file))
		if err != nil {
			return err
		}
		sv, err := signerVerifier(k.scheme, pem)
		if err != nil {
			return fmt.Errorf("%s: %w", k.file, err)
		}
		signer, err := dsse.NewEnvelopeSigner(sv)
		if err != nil {
			return err
		}
		env, err := signer.SignPayload(context.Background(), payloadType, []byte(payload))
		if err != nil {
			return fmt.Errorf("%s: sign: %w", k.file, err)
		}
		pubPem, err := os.ReadFile(filepath.Join(keysDir, strings.Replace(k.file, ".key.pem", ".pub.pem", 1)))
		if err != nil {
			return err
		}
		keyID, err := sv.KeyID()
		if err != nil {
			return err
		}
		f := fixture{Implementation: "go-securesystemslib", Version: version(), Scheme: k.scheme, KeyID: keyID, PublicKeyPem: string(pubPem), Envelope: env}
		out, err := json.MarshalIndent(f, "", "  ")
		if err != nil {
			return err
		}
		name := filepath.Join(outDir, "go-"+k.scheme+".json")
		if err := os.WriteFile(name, append(out, '\n'), 0o644); err != nil {
			return err
		}
		fmt.Println("wrote", name)
	}
	return nil
}

func verify(dir string) error {
	files, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return err
	}
	if len(files) == 0 {
		return fmt.Errorf("no fixtures in %s", dir)
	}
	for _, file := range files {
		raw, err := os.ReadFile(file)
		if err != nil {
			return err
		}
		var f fixture
		if err := json.Unmarshal(raw, &f); err != nil {
			return fmt.Errorf("%s: %w", file, err)
		}
		if strings.HasPrefix(f.Scheme, "rsa-pkcs1v15") {
			fmt.Println("skip ", file, "(go-securesystemslib has no PKCS#1 v1.5 verifier)")
			continue
		}
		sv, err := signerVerifier(f.Scheme, []byte(f.PublicKeyPem))
		if err != nil {
			return fmt.Errorf("%s: %w", file, err)
		}
		// The key id is an opaque hint in DSSE; take the envelope's, as a consumer that
		// resolved the key by it would.
		verifier, err := dsse.NewEnvelopeVerifier(&namedVerifier{Verifier: sv, id: f.KeyID})
		if err != nil {
			return err
		}
		if _, err := verifier.Verify(context.Background(), f.Envelope); err != nil {
			return fmt.Errorf("%s: %w", file, err)
		}
		fmt.Println("ok   ", file)
	}
	return nil
}

// namedVerifier reports the envelope's key id instead of the SSLib-computed one.
type namedVerifier struct {
	dsse.Verifier
	id string
}

func (v *namedVerifier) KeyID() (string, error) { return v.id, nil }

func signerVerifier(scheme string, pem []byte) (dsse.SignerVerifier, error) {
	switch {
	case strings.HasPrefix(scheme, "ecdsa-"):
		key, err := signerverifier.LoadKey(pem)
		if err != nil {
			return nil, err
		}
		return signerverifier.NewECDSASignerVerifierFromSSLibKey(key)
	case scheme == "ed25519":
		key, err := signerverifier.LoadKey(pem)
		if err != nil {
			return nil, err
		}
		return signerverifier.NewED25519SignerVerifierFromSSLibKey(key)
	case scheme == "rsassa-pss-sha256":
		key, err := signerverifier.LoadRSAPSSKeyFromBytes(pem)
		if err != nil {
			return nil, err
		}
		return signerverifier.NewRSAPSSSignerVerifierFromSSLibKey(key)
	}
	return nil, fmt.Errorf("unsupported scheme %q", scheme)
}

func version() string {
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, dep := range info.Deps {
			if dep.Path == "github.com/secure-systems-lab/go-securesystemslib" {
				return dep.Version
			}
		}
	}
	return "unknown"
}
