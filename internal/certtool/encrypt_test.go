// Copyright 2026 Cloudfra
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package certtool

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
	certlib "github.com/cloudfra/certtool/pkg/certtool"
)

// newAgeIdentity returns an age identity, and the path of an identity file
// that holds it.
func newAgeIdentity(t *testing.T) (*age.X25519Identity, string) {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "identity.txt")
	if err := os.WriteFile(path, []byte("# test identity\n"+id.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return id, path
}

func decryptFile(t *testing.T, path string, id age.Identity) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	plain, err := certlib.DecryptPrivateData(data, []age.Identity{id})
	if err != nil {
		t.Fatalf("DecryptPrivateData(%s) err = %v", path, err)
	}
	return plain
}

func TestRunEncryptsKey(t *testing.T) {
	t.Parallel()
	id, _ := newAgeIdentity(t)
	args := testArgs(t)
	args.EncryptTo = id.Recipient().String()
	if err := Run(t.Context(), args); err != nil {
		t.Fatalf("Run() err = %v", err)
	}

	if _, err := os.Stat(args.PrivateKey); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("%s was written unencrypted", args.PrivateKey)
	}
	cert, err := os.ReadFile(args.PublicCertificate)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := certlib.ReadKeyPair(cert, decryptFile(t, args.PrivateKey+certlib.EncryptedSuffix, id)); err != nil {
		t.Errorf("the decrypted key does not match the certificate: %v", err)
	}
}

// An encrypted .pfx is protected even without its own password, so certtool
// does not warn about it.
func TestRunEncryptsPFX(t *testing.T) {
	t.Setenv(PFXPasswordEnv, "")
	ctx, logs := captureWarnings(t)
	id, _ := newAgeIdentity(t)
	args := testArgs(t)
	args.CodeSigning, args.Target = true, defaultCodeSignTarget
	args.EncryptTo = id.Recipient().String()
	if err := Run(ctx, args); err != nil {
		t.Fatalf("Run() err = %v", err)
	}
	if len(decryptFile(t, args.PFXOutput+certlib.EncryptedSuffix, id)) == 0 {
		t.Error("the decrypted .pfx is empty")
	}
	if strings.Contains(logs.String(), "no password") {
		t.Errorf("warned about a .pfx without a password although it is encrypted:\n%s", logs)
	}
}

func TestRunSpecReusesEncryptedKeys(t *testing.T) {
	t.Parallel()
	id, identityFile := newAgeIdentity(t)
	args := testArgs(t)
	args.Chain = "1,1"
	args.EncryptTo = id.Recipient().String()
	if err := Run(t.Context(), args); err != nil {
		t.Fatalf("Run() err = %v", err)
	}
	keys, err := filepath.Glob(filepath.Join(args.OutputDir, "*.key*"))
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range keys {
		if !strings.HasSuffix(key, ".key.age") {
			t.Errorf("%s is not encrypted", key)
		}
	}

	// Reusing the encrypted keys needs an identity.
	if err := Run(t.Context(), args); err == nil || !strings.Contains(err.Error(), "encrypted with age") || !strings.Contains(err.Error(), "--age-yubikey") {
		t.Errorf("Run() without an identity err = %v, want one saying the key is encrypted and how to decrypt it", err)
	}
	args.AgeIdentityFile = identityFile
	if err := Run(t.Context(), args); err != nil {
		t.Errorf("Run() with --age-identity-file err = %v", err)
	}
}

func TestRunDecryptsParentKey(t *testing.T) {
	t.Parallel()
	id, identityFile := newAgeIdentity(t)
	parent := testArgs(t)
	parent.CA = true
	parent.EncryptTo = id.Recipient().String()
	if err := Run(t.Context(), parent); err != nil {
		t.Fatalf("Run() for the parent err = %v", err)
	}

	child := testArgs(t)
	child.ParentPublicCertificate = parent.PublicCertificate
	child.ParentPrivateKey = parent.PrivateKey + certlib.EncryptedSuffix
	if err := Run(t.Context(), child); err == nil || !strings.Contains(err.Error(), "--age-identity-file") {
		t.Errorf("Run() without an identity err = %v, want it to name --age-identity-file", err)
	}
	child.AgeIdentityFile = identityFile
	if err := Run(t.Context(), child); err != nil {
		t.Fatalf("Run() with --age-identity-file err = %v", err)
	}
}

func TestRunDecryptsWithIdentityEnv(t *testing.T) {
	id, _ := newAgeIdentity(t)
	t.Setenv(AgeIdentityEnv, id.String())
	args := testArgs(t)
	args.Chain = "1"
	args.EncryptTo = id.Recipient().String()
	for range 2 {
		if err := Run(t.Context(), args); err != nil {
			t.Fatalf("Run() err = %v", err)
		}
	}

	t.Setenv(AgeIdentityEnv, "not an identity")
	err := Run(t.Context(), args)
	if err == nil || !strings.Contains(err.Error(), AgeIdentityEnv) || strings.Contains(err.Error(), "not an identity") {
		t.Errorf("Run() err = %v, want one naming %s without repeating its value", err, AgeIdentityEnv)
	}
}

func TestRunEncryptionErrors(t *testing.T) {
	t.Parallel()
	id, identityFile := newAgeIdentity(t)
	badFile := filepath.Join(t.TempDir(), "plugin-identity.txt")
	if err := os.WriteFile(badFile, []byte("AGE-PLUGIN-YUBIKEY-1XYZ\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		edit func(*Args)
		want string
	}{
		{"bad recipient", func(a *Args) { a.EncryptTo = "age1nope" }, "--encrypt-to"},
		{"export spec", func(a *Args) {
			a.EncryptTo, a.ExportSpec = id.Recipient().String(), filepath.Join(a.OutputDir, "x.yaml")
		}, "--export-spec, which writes no keys"},
		{"generate root", func(a *Args) { a.EncryptTo, a.YubiKeyGenerateRoot = id.Recipient().String(), true }, "--yubikey-generate-root"},
		{"nothing to decrypt", func(a *Args) { a.AgeIdentityFile = identityFile }, "nothing to decrypt"},
		{"missing identity file", func(a *Args) { a.Chain, a.AgeIdentityFile = "1", filepath.Join(a.OutputDir, "missing.txt") }, "--age-identity-file"},
		{"plugin identity file", func(a *Args) { a.Chain, a.AgeIdentityFile = "1", badFile }, "use --age-yubikey"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			args := testArgs(t)
			tc.edit(&args)
			if err := Run(t.Context(), args); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("Run() err = %v, want an error containing %q", err, tc.want)
			}
		})
	}
}
