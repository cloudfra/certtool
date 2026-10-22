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
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
	"filippo.io/age/plugin"
	"filippo.io/age/tag"
)

// newP256Key returns a software P-256 key, standing in for a YubiKey slot.
func newP256Key(t *testing.T) *ecdh.PrivateKey {
	t.Helper()
	key, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// yubiKeyRecipient returns the age1yubikey recipient of key, as
// age-plugin-yubikey prints it.
func yubiKeyRecipient(key *ecdh.PrivateKey) string {
	return plugin.EncodeRecipient("yubikey", compress(key.PublicKey()))
}

// tagRecipient returns the age1tag recipient of key.
func tagRecipient(t *testing.T, key *ecdh.PrivateKey) string {
	t.Helper()
	r, err := tag.NewClassicRecipient(compress(key.PublicKey()))
	if err != nil {
		t.Fatal(err)
	}
	return r.String()
}

func testP256Identity(t *testing.T, key *ecdh.PrivateKey) age.Identity {
	t.Helper()
	id, err := NewP256Identity(key)
	if err != nil {
		t.Fatalf("NewP256Identity() err = %v", err)
	}
	return id
}

func parseRecipients(t *testing.T, recipients ...string) []age.Recipient {
	t.Helper()
	parsed := make([]age.Recipient, len(recipients))
	for i, s := range recipients {
		r, err := ParseAgeRecipient(s)
		if err != nil {
			t.Fatalf("ParseAgeRecipient(%q) err = %v", s, err)
		}
		parsed[i] = r
	}
	return parsed
}

func TestEncryptPrivateDataRoundTrip(t *testing.T) {
	t.Parallel()
	x25519, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	hybrid, err := age.GenerateHybridIdentity()
	if err != nil {
		t.Fatal(err)
	}
	pivKey, tagKey := newP256Key(t), newP256Key(t)

	for _, tc := range []struct {
		name      string
		recipient string
		identity  age.Identity
	}{
		{"x25519", x25519.Recipient().String(), x25519},
		{"post-quantum", hybrid.Recipient().String(), hybrid},
		{"age1yubikey", yubiKeyRecipient(pivKey), testP256Identity(t, pivKey)},
		{"age1tag", tagRecipient(t, tagKey), testP256Identity(t, tagKey)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			plain := []byte("-----BEGIN EC PRIVATE KEY-----\nsecret\n-----END EC PRIVATE KEY-----\n")
			data, err := EncryptPrivateData(plain, parseRecipients(t, tc.recipient))
			if err != nil {
				t.Fatalf("EncryptPrivateData() err = %v", err)
			}
			if !IsAgeEncrypted(data) || bytes.Contains(data, []byte("secret")) {
				t.Fatalf("EncryptPrivateData() did not encrypt:\n%s", data)
			}
			got, err := DecryptPrivateData(data, []age.Identity{tc.identity})
			if err != nil {
				t.Fatalf("DecryptPrivateData() err = %v", err)
			}
			if !bytes.Equal(got, plain) {
				t.Errorf("DecryptPrivateData() = %q, want %q", got, plain)
			}

			// Another key must not decrypt it.
			if _, err := DecryptPrivateData(data, []age.Identity{testP256Identity(t, newP256Key(t))}); err == nil {
				t.Error("DecryptPrivateData() with another key err = nil")
			}
		})
	}
}

// TestDecryptPrivateDataManyRecipients checks that a YubiKey identity finds
// its stanza among others, as when a key is encrypted to a backup too.
func TestDecryptPrivateDataManyRecipients(t *testing.T) {
	t.Parallel()
	backup, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	yubiKey, other := newP256Key(t), newP256Key(t)
	data, err := EncryptPrivateData([]byte("key"), parseRecipients(t, yubiKeyRecipient(other), backup.Recipient().String(), tagRecipient(t, yubiKey)))
	if err != nil {
		t.Fatal(err)
	}
	for name, id := range map[string]age.Identity{"backup": backup, "yubikey": testP256Identity(t, yubiKey), "other": testP256Identity(t, other)} {
		if got, err := DecryptPrivateData(data, []age.Identity{id}); err != nil || string(got) != "key" {
			t.Errorf("%s: DecryptPrivateData() = %q, %v", name, got, err)
		}
	}
}

func TestParseAgeRecipientErrors(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		recipient string
		want      string
	}{
		{plugin.EncodeRecipient("fido2-hmac", []byte{1, 2, 3}), "age-plugin-fido2-hmac"},
		{plugin.EncodeRecipient("yubikey", []byte{1, 2, 3}), "compressed P-256"},
		{"ssh-ed25519 AAAA", "not an age recipient"},
		{"", "not an age recipient"},
	} {
		if _, err := ParseAgeRecipient(tc.recipient); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("ParseAgeRecipient(%q) err = %v, want an error containing %q", tc.recipient, err, tc.want)
		}
	}
}

func TestNewP256IdentityRejectsOtherCurves(t *testing.T) {
	t.Parallel()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewP256Identity(key); err == nil {
		t.Error("NewP256Identity(X25519 key) err = nil")
	}
}

func TestGenerateFromSpecEncrypted(t *testing.T) {
	t.Parallel()
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	enc := &KeyEncryption{Recipients: []age.Recipient{identity.Recipient()}, Identities: []age.Identity{identity}}
	dir := t.TempDir()
	signer := CertificateSpec{CommonName: "Signer", CodeSigning: true, PFXPassword: "pw", Filename: "signer"}
	specs := append(reuseSpec("api"), signer)

	out, err := GenerateFromSpecWithOptions(specs, dir, SpecOptions{Encryption: enc})
	if err != nil {
		t.Fatalf("GenerateFromSpecWithOptions() err = %v", err)
	}
	for _, o := range out {
		if !strings.HasSuffix(o.KeyPath, ".key.age") {
			t.Errorf("%s: KeyPath = %q, want an encrypted .key.age", o.CommonName, o.KeyPath)
		}
	}
	for _, name := range []string{"root.key", "api.key", "signer.key", "signer.pfx"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
			t.Errorf("%s was written unencrypted", name)
		}
		data, err := os.ReadFile(filepath.Clean(filepath.Join(dir, name+EncryptedSuffix)))
		if err != nil {
			t.Fatalf("%s: %v", name+EncryptedSuffix, err)
		}
		if !IsAgeEncrypted(data) {
			t.Errorf("%s is not encrypted", name+EncryptedSuffix)
		}
	}

	t.Run("reuse", func(t *testing.T) {
		out, err := GenerateFromSpecWithOptions(append(reuseSpec("api", "web"), signer), dir, SpecOptions{Encryption: enc})
		if err != nil {
			t.Fatalf("GenerateFromSpecWithOptions() err = %v", err)
		}
		reused, generated := reusedNames(out)
		if strings.Join(reused, ",") != "Reuse Root CA,api,Signer" || strings.Join(generated, ",") != "web" {
			t.Errorf("reused %v and generated %v, want the existing certificates reused and web generated", reused, generated)
		}
	})

	t.Run("reuse without identity", func(t *testing.T) {
		_, err := GenerateFromSpecWithOptions(reuseSpec("api"), dir, SpecOptions{})
		if !errors.Is(err, ErrExistingFiles) || !errors.Is(err, ErrNoAgeIdentity) {
			t.Errorf("GenerateFromSpecWithOptions() err = %v, want ErrExistingFiles saying the key is encrypted", err)
		}
	})
}

func TestGenerateFromSpecOverwriteChangesEncryption(t *testing.T) {
	t.Parallel()
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	enc := &KeyEncryption{Recipients: []age.Recipient{identity.Recipient()}}
	dir := t.TempDir()

	if _, err := GenerateFromSpec(reuseSpec(), dir); err != nil {
		t.Fatal(err)
	}
	if _, err := GenerateFromSpecWithOptions(reuseSpec(), dir, SpecOptions{Overwrite: true, Encryption: enc}); err != nil {
		t.Fatalf("GenerateFromSpecWithOptions() err = %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "root.key")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the plain root.key is still there after regenerating it encrypted: %v", err)
	}

	// With both forms present, certtool cannot tell which is current.
	if err := os.WriteFile(filepath.Join(dir, "root.key"), []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := GenerateFromSpecWithOptions(reuseSpec(), dir, SpecOptions{Encryption: enc}); !errors.Is(err, ErrExistingFiles) || !strings.Contains(err.Error(), "both") {
		t.Errorf("GenerateFromSpecWithOptions() err = %v, want ErrExistingFiles naming both files", err)
	}
}

func TestReadKeyPairFromFileEncrypted(t *testing.T) {
	t.Parallel()
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	kp, err := GenerateKeyPair(&Args{CA: true, CommonName: "Parent"})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "parent.crt"), filepath.Join(dir, "parent.key")
	enc := &KeyEncryption{Recipients: []age.Recipient{identity.Recipient()}}
	written, err := enc.WriteKeyPair(kp, certPath, keyPath)
	if err != nil {
		t.Fatalf("WriteKeyPair() err = %v", err)
	}

	if _, err := ReadKeyPairFromFile(certPath, written); err == nil {
		t.Error("ReadKeyPairFromFile() of an encrypted key err = nil")
	}
	var none *KeyEncryption
	if _, err := none.ReadKeyPairFromFile(certPath, written); err == nil || !strings.Contains(err.Error(), "no identity") {
		t.Errorf("ReadKeyPairFromFile() without identities err = %v, want one saying no identity was given", err)
	}
	got, err := (&KeyEncryption{Identities: []age.Identity{identity}}).ReadKeyPairFromFile(certPath, written)
	if err != nil {
		t.Fatalf("ReadKeyPairFromFile() err = %v", err)
	}
	if !bytes.Equal(got.PrivateKey, kp.PrivateKey) {
		t.Error("ReadKeyPairFromFile() returned a different key")
	}
	if _, _, err := ReadKeyPair(got.PublicCertificate, got.PrivateKey); err != nil {
		t.Errorf("ReadKeyPair() of the decrypted key err = %v", err)
	}
}

func TestReadKeyPairAgeGuidance(t *testing.T) {
	t.Parallel()
	kp, err := GenerateKeyPair(&Args{CommonName: "x"})
	if err != nil {
		t.Fatal(err)
	}
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	data, err := EncryptPrivateData(kp.PrivateKey, []age.Recipient{identity.Recipient()})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := ReadKeyPair(kp.PublicCertificate, data); err == nil || !strings.Contains(err.Error(), "--age-identity-file") {
		t.Errorf("ReadKeyPair() err = %v, want guidance naming --age-identity-file", err)
	}
}
