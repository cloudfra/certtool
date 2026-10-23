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

//go:build windows || (cgo && ((linux && !android) || (darwin && !ios) || freebsd || openbsd))

package yubikey

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"filippo.io/age/plugin"
	"filippo.io/age/tag"
	"filippo.io/nistec"
	"github.com/cloudfra/certtool/pkg/certtool"
	"github.com/go-piv/piv-go/v2/piv"
)

// putAgeKey stores a P-256 key in slot, as age-plugin-yubikey --generate
// does, and returns its age1yubikey and age1tag recipients.
func putAgeKey(t *testing.T, card *fakeCard, slot piv.Slot) (yubiKeyRecipient, tagRecipient string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	card.keys[slot.Key] = key
	// The plugin also stores a self-signed certificate, which older firmware
	// needs to find the public key.
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "age identity"}, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	if card.certs[slot.Key], err = x509.ParseCertificate(der); err != nil {
		t.Fatal(err)
	}

	uncompressed, err := key.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	point, err := nistec.NewP256Point().SetBytes(uncompressed)
	if err != nil {
		t.Fatal(err)
	}
	compressed := point.BytesCompressed()
	tagged, err := tag.NewClassicRecipient(compressed)
	if err != nil {
		t.Fatal(err)
	}
	return plugin.EncodeRecipient("yubikey", compressed), tagged.String()
}

func encryptTo(t *testing.T, recipient string, data string) []byte {
	t.Helper()
	r, err := certtool.ParseAgeRecipient(recipient)
	if err != nil {
		t.Fatal(err)
	}
	out, err := certtool.EncryptPrivateData([]byte(data), []age.Recipient{r})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestAgeIdentities(t *testing.T) {
	for _, tc := range []struct {
		name    string
		version piv.Version
	}{
		{"key metadata", piv.Version{Major: 5, Minor: 4, Patch: 3}},
		{"certificate on old firmware", piv.Version{Major: 5, Minor: 2, Patch: 7}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			card := newFakeCard(fakeSerial)
			card.version = tc.version
			slot, _ := piv.RetiredKeyManagementSlot(0x83)
			yubiKeyRecipient, tagRecipient := putAgeKey(t, card, slot)
			// A root CA in 9c is not an age key.
			putRoot(t, card, piv.SlotSignature, nil)

			decrypts := 0
			token := openFake(t, card, Config{PIN: fakePIN, BeforeDecrypt: func() { decrypts++ }})
			identities, err := token.AgeIdentities()
			if err != nil {
				t.Fatalf("AgeIdentities() err = %v", err)
			}
			if len(identities) != 1 {
				t.Fatalf("AgeIdentities() returned %d identities, want 1 for slot 83", len(identities))
			}

			for _, recipient := range []string{yubiKeyRecipient, tagRecipient} {
				got, err := certtool.DecryptPrivateData(encryptTo(t, recipient, "secret key"), identities)
				if err != nil {
					t.Fatalf("DecryptPrivateData(%s) err = %v", recipient[:12], err)
				}
				if string(got) != "secret key" {
					t.Errorf("DecryptPrivateData() = %q", got)
				}
			}
			if decrypts != 2 || card.decrypts != 2 {
				t.Errorf("BeforeDecrypt called %d times and the YubiKey decrypted %d times, want 2 and 2", decrypts, card.decrypts)
			}
		})
	}
}

func TestAgeIdentitiesErrors(t *testing.T) {
	t.Run("no age key", func(t *testing.T) {
		card := newFakeCard(fakeSerial)
		putRoot(t, card, piv.SlotSignature, nil)
		token := openFake(t, card, Config{PIN: fakePIN})
		if _, err := token.AgeIdentities(); err == nil || !strings.Contains(err.Error(), "age-plugin-yubikey --generate") {
			t.Errorf("AgeIdentities() err = %v, want one saying how to create an age key", err)
		}
	})

	t.Run("wrong PIN", func(t *testing.T) {
		card := newFakeCard(fakeSerial)
		recipient, _ := putAgeKey(t, card, piv.SlotKeyManagement)
		token := openFake(t, card, Config{PIN: "654321"})
		identities, err := token.AgeIdentities()
		if err != nil {
			t.Fatalf("AgeIdentities() err = %v", err)
		}
		data := encryptTo(t, recipient, "secret")
		if _, err := certtool.DecryptPrivateData(data, identities); err == nil || !strings.Contains(err.Error(), "slot 9d") {
			t.Errorf("DecryptPrivateData() err = %v, want an error naming slot 9d", err)
		}
		// The PIN is not tried again, so it cannot be blocked.
		if _, err := certtool.DecryptPrivateData(data, identities); err == nil || !strings.Contains(err.Error(), "already rejected") {
			t.Errorf("second DecryptPrivateData() err = %v, want the PIN not to be tried again", err)
		}
		if card.retries != 2 {
			t.Errorf("PIN retries = %d, want 2: one wrong attempt only", card.retries)
		}
	})
}
