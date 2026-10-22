// Copyright 2022 Jeremy Edwards
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
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cloudfra/certtool/pkg/certtool"
	"github.com/go-piv/piv-go/v2/piv"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

const (
	yubiKeyReader  = "Yubico YubiKey OTP+FIDO+CCID 00 00"
	yubiKeyReader2 = "Yubico YubiKey OTP+FIDO+CCID 01 00"
	otherReader    = "Generic Smart Card Reader 00 00"
	tokenPrefix    = "YubiKey 1234567 (firmware 5.4.3), slot 9c: "
)

// wantErr fails the test unless err is non-nil and contains every substring.
func wantErr(t *testing.T, err error, substrings ...string) {
	t.Helper()

	if err == nil {
		t.Fatalf("err = nil, want an error containing %q", substrings)
	}
	for _, s := range substrings {
		if !strings.Contains(err.Error(), s) {
			t.Errorf("err = %q\nwant it to contain %q", err, s)
		}
	}
}

func pinConfig() Config {
	return Config{PIN: fakePIN}
}

func signLeaf(t *testing.T, issuer *certtool.Issuer) (*x509.Certificate, error) {
	t.Helper()

	kp, err := certtool.GenerateKeyPair(&certtool.Args{
		CommonName: "leaf.example.com",
		Hostnames:  []string{"leaf.example.com"},
		KeyType:    &certtool.KeyType{Algorithm: "ECDSA", KeyLength: 256},
		Issuer:     issuer,
	})
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(kp.PublicCertificate)
	return x509.ParseCertificate(block.Bytes)
}

func verifyChain(t *testing.T, root *x509.Certificate, leaf *x509.Certificate) {
	t.Helper()

	roots := x509.NewCertPool()
	roots.AddCert(root)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots}); err != nil {
		t.Errorf("leaf does not chain to the YubiKey root: %v", err)
	}
}

func TestOpen(t *testing.T) {
	card := newFakeCard(fakeSerial)
	installFakes(t, []string{otherReader, yubiKeyReader}, map[string]*fakeCard{yubiKeyReader: card}, nil)

	token, err := Open(Config{})
	if err != nil {
		t.Fatalf("Open() err = %v", err)
	}
	if token.Serial() != fakeSerial {
		t.Errorf("Serial() = %d, want %d", token.Serial(), fakeSerial)
	}
	if err := token.Close(); err != nil {
		t.Errorf("Close() err = %v", err)
	}
	// Opened once to read the serial number and once to use it.
	if card.opens != 2 || card.closes != 2 {
		t.Errorf("opens = %d, closes = %d, want 2 and 2", card.opens, card.closes)
	}
}

func TestOpen_SelectsBySerial(t *testing.T) {
	first, second := newFakeCard(111), newFakeCard(222)
	installFakes(t, []string{yubiKeyReader, yubiKeyReader2}, map[string]*fakeCard{yubiKeyReader: first, yubiKeyReader2: second}, nil)

	token, err := Open(Config{Serial: 222})
	if err != nil {
		t.Fatalf("Open() err = %v", err)
	}
	if token.Serial() != 222 {
		t.Errorf("Serial() = %d, want 222", token.Serial())
	}
	if first.opens != first.closes {
		t.Errorf("unselected YubiKey left open: opens = %d, closes = %d", first.opens, first.closes)
	}
}

func TestOpen_Errors(t *testing.T) {
	testCases := []struct {
		name    string
		readers []string
		cards   map[string]*fakeCard
		listErr error
		cfg     Config
		want    []string
	}{
		{
			name:    "pcsc unavailable",
			listErr: errors.New("connecting to pcsc: the Smart card resource manager is not running"),
			want:    []string{"cannot list smart card readers", pcscHint(), "the Smart card resource manager is not running"},
		},
		{
			name: "no readers",
			want: []string{"no YubiKey is connected, no smart card readers were found", "CCID"},
		},
		{
			name:    "only other readers",
			readers: []string{otherReader},
			want:    []string{"no YubiKey is connected", otherReader},
		},
		{
			name:    "several YubiKeys",
			readers: []string{yubiKeyReader, yubiKeyReader2},
			cards:   map[string]*fakeCard{yubiKeyReader: newFakeCard(111), yubiKeyReader2: newFakeCard(222)},
			want:    []string{"more than one YubiKey is connected (serial numbers 111, 222)", "select one by serial number"},
		},
		{
			name:    "serial not connected",
			readers: []string{yubiKeyReader},
			cards:   map[string]*fakeCard{yubiKeyReader: newFakeCard(111)},
			cfg:     Config{Serial: 999},
			want:    []string{"YubiKey with serial number 999 is not connected", "serial numbers 111"},
		},
		{
			name:    "in use",
			readers: []string{yubiKeyReader},
			cards:   map[string]*fakeCard{yubiKeyReader: {openErr: errors.New("sharing violation")}},
			want:    []string{"cannot open YubiKey", yubiKeyReader, "gpg-agent", "sharing violation"},
		},
		{
			name:    "one of several in use",
			readers: []string{yubiKeyReader, yubiKeyReader2},
			cards:   map[string]*fakeCard{yubiKeyReader: {openErr: errors.New("sharing violation")}, yubiKeyReader2: newFakeCard(222)},
			want:    []string{"cannot open YubiKey", yubiKeyReader, "sharing violation"},
		},
		{
			name:    "serial not connected and another in use",
			readers: []string{yubiKeyReader, yubiKeyReader2},
			cards:   map[string]*fakeCard{yubiKeyReader: {openErr: errors.New("sharing violation")}, yubiKeyReader2: newFakeCard(222)},
			cfg:     Config{Serial: 999},
			want:    []string{"cannot open YubiKey", yubiKeyReader, "sharing violation"},
		},
		{
			name:    "serial unreadable",
			readers: []string{yubiKeyReader},
			cards:   map[string]*fakeCard{yubiKeyReader: {serialErr: errors.New("transmit failed")}},
			want:    []string{"cannot read the serial number of YubiKey", "transmit failed"},
		},
		{
			name: "bad slot",
			cfg:  Config{Slot: "f9"},
			want: []string{`YubiKey slot "f9" is not a PIV key slot`},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			installFakes(t, tc.readers, tc.cards, tc.listErr)
			token, err := Open(tc.cfg)
			if token != nil {
				t.Errorf("Open() token = %v, want nil", token)
			}
			wantErr(t, err, tc.want...)
		})
	}
}

func TestIssuer(t *testing.T) {
	card := newFakeCard(fakeSerial)
	root := putRoot(t, card, piv.SlotSignature, nil)

	signs := 0
	token := openFake(t, card, Config{
		PIN:        fakePIN,
		BeforeSign: func() { signs++ },
	})

	issuer, err := token.Issuer()
	if err != nil {
		t.Fatalf("Issuer() err = %v", err)
	}
	if !issuer.Certificate.Equal(root) {
		t.Error("Issuer().Certificate is not the certificate in the slot")
	}

	for range 2 {
		leaf, err := signLeaf(t, issuer)
		if err != nil {
			t.Fatalf("signing with the YubiKey issuer err = %v", err)
		}
		verifyChain(t, root, leaf)
	}

	// PINPolicyAlways: the PIN is verified for every signature.
	if card.pinAttempts != 2 {
		t.Errorf("PIN verified %d times, want 2", card.pinAttempts)
	}
	if signs != 2 || card.signs != 2 {
		t.Errorf("BeforeSign called %d times and YubiKey signed %d times, want 2 and 2", signs, card.signs)
	}
}

// A YubiKey that cannot be opened does not stop another one from being
// selected by serial number.
func TestOpen_SelectsBySerialWhileAnotherIsInUse(t *testing.T) {
	want := newFakeCard(222)
	installFakes(t, []string{yubiKeyReader, yubiKeyReader2}, map[string]*fakeCard{
		yubiKeyReader:  {openErr: errors.New("sharing violation")},
		yubiKeyReader2: want,
	}, nil)

	token, err := Open(Config{Serial: 222})
	if err != nil {
		t.Fatalf("Open() err = %v", err)
	}
	if token.Serial() != 222 || token.yk != want {
		t.Errorf("Open() opened YubiKey %d, want 222", token.Serial())
	}
}

// Looking up the PIN policy fails for keys imported onto firmware older than
// 5.3, so the PIN is then verified before every signature.
func TestIssuer_UnknownPINPolicy(t *testing.T) {
	card := newFakeCard(fakeSerial)
	card.pinPolicyErr = errors.New("get attestation cert: smart card error 6a80")
	root := putRoot(t, card, piv.SlotSignature, nil)
	token := openFake(t, card, pinConfig())

	issuer, err := token.Issuer()
	if err != nil {
		t.Fatalf("Issuer() err = %v", err)
	}
	leaf, err := signLeaf(t, issuer)
	if err != nil {
		t.Fatal(err)
	}
	verifyChain(t, root, leaf)
}

func TestIssuer_OtherSlot(t *testing.T) {
	card := newFakeCard(fakeSerial)
	slot, _ := piv.RetiredKeyManagementSlot(0x82)
	root := putRoot(t, card, slot, nil)
	token := openFake(t, card, Config{Slot: "82", PIN: fakePIN})

	issuer, err := token.Issuer()
	if err != nil {
		t.Fatalf("Issuer() err = %v", err)
	}
	leaf, err := signLeaf(t, issuer)
	if err != nil {
		t.Fatal(err)
	}
	verifyChain(t, root, leaf)
}

func TestIssuer_SlotErrors(t *testing.T) {
	testCases := []struct {
		name   string
		mutate func(*x509.Certificate)
		setup  func(*fakeCard)
		want   []string
	}{
		{
			name:  "empty slot",
			setup: func(c *fakeCard) { delete(c.certs, piv.SlotSignature.Key) },
			want:  []string{tokenPrefix, "there is no certificate in the slot", "generate a root CA"},
		},
		{
			name:  "unreadable certificate",
			setup: func(c *fakeCard) { c.certErr = errors.New("parsing certificate: x509: malformed") },
			want:  []string{tokenPrefix, "cannot read the certificate", "malformed"},
		},
		{
			name:   "not a CA",
			mutate: func(c *x509.Certificate) { c.IsCA = false },
			want:   []string{tokenPrefix, `the certificate "Fake Root CA" is not a CA certificate`},
		},
		{
			name:   "no cert sign usage",
			mutate: func(c *x509.Certificate) { c.KeyUsage = x509.KeyUsageDigitalSignature },
			want:   []string{tokenPrefix, "does not allow certificate signing"},
		},
		{
			name: "expired",
			mutate: func(c *x509.Certificate) {
				c.NotBefore = time.Now().Add(-2 * time.Hour)
				c.NotAfter = time.Now().Add(-time.Hour)
			},
			want: []string{tokenPrefix, `the certificate "Fake Root CA" expired at`},
		},
		{
			name:   "not yet valid",
			mutate: func(c *x509.Certificate) { c.NotBefore = time.Now().Add(time.Hour) },
			want:   []string{tokenPrefix, "is not valid until"},
		},
		{
			name:  "no private key",
			setup: func(c *fakeCard) { delete(c.keys, piv.SlotSignature.Key) },
			want:  []string{tokenPrefix, "cannot use the private key", "not found"},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			card := newFakeCard(fakeSerial)
			putRoot(t, card, piv.SlotSignature, tc.mutate)
			if tc.setup != nil {
				tc.setup(card)
			}
			token := openFake(t, card, pinConfig())

			issuer, err := token.Issuer()
			if issuer != nil {
				t.Errorf("Issuer() = %v, want nil", issuer)
			}
			wantErr(t, err, tc.want...)
		})
	}
}

func TestIssuer_KeyDoesNotMatchCertificate(t *testing.T) {
	card := newFakeCard(fakeSerial)
	putRoot(t, card, piv.SlotSignature, nil)
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	card.keys[piv.SlotSignature.Key] = other
	token := openFake(t, card, pinConfig())

	issuer, err := token.Issuer()
	if err != nil {
		t.Fatalf("Issuer() err = %v", err)
	}
	_, err = signLeaf(t, issuer)
	wantErr(t, err, tokenPrefix, "the private key in the slot does not match the certificate stored there")
}

func TestIssuer_PINErrors(t *testing.T) {
	testCases := []struct {
		name         string
		cfg          Config
		retries      int
		signErr      error
		want         []string
		wantAttempts int
	}{
		{
			name:         "wrong PIN",
			cfg:          Config{PIN: "654321"},
			retries:      3,
			want:         []string{tokenPrefix, "cannot sign", "the PIN is incorrect, 2 attempts remain before it is blocked"},
			wantAttempts: 1,
		},
		{
			name:         "last attempt",
			cfg:          Config{PIN: "654321"},
			retries:      2,
			want:         []string{"the PIN is incorrect, 1 attempt remains before it is blocked"},
			wantAttempts: 1,
		},
		{
			name:         "blocked PIN",
			cfg:          pinConfig(),
			retries:      0,
			want:         []string{tokenPrefix, "the PIN is blocked", "unblock-pin"},
			wantAttempts: 1,
		},
		{
			name: "PIN too short",
			cfg:  Config{PIN: "123"},
			want: []string{tokenPrefix, "the PIN must be 6 to 8 characters but is 3, so it was not sent to the YubiKey"},
		},
		{
			name: "PIN too long",
			cfg:  Config{PIN: "123456789"},
			want: []string{"the PIN must be 6 to 8 characters but is 9"},
		},
		{
			name: "no PIN",
			want: []string{tokenPrefix, "a PIN is needed but none was provided"},
		},
		{
			name:    "touch timeout",
			cfg:     pinConfig(),
			signErr: errors.New("smart card error 6982: security status not satisfied"),
			want:    []string{tokenPrefix, "cannot sign", "not touched in time", "touch the YubiKey when it blinks"},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			card := newFakeCard(fakeSerial)
			card.retries = tc.retries
			card.signErr = tc.signErr
			putRoot(t, card, piv.SlotSignature, nil)
			token := openFake(t, card, tc.cfg)

			issuer, err := token.Issuer()
			if err != nil {
				t.Fatalf("Issuer() err = %v", err)
			}
			_, err = signLeaf(t, issuer)
			wantErr(t, err, tc.want...)
			if card.pinAttempts != tc.wantAttempts {
				t.Errorf("PIN attempts = %d, want %d", card.pinAttempts, tc.wantAttempts)
			}
		})
	}
}

func TestIssuer_RejectedPINIsNotRetried(t *testing.T) {
	card := newFakeCard(fakeSerial)
	putRoot(t, card, piv.SlotSignature, nil)
	token := openFake(t, card, Config{PIN: "654321"})

	issuer, err := token.Issuer()
	if err != nil {
		t.Fatal(err)
	}

	_, err = signLeaf(t, issuer)
	var authErr piv.AuthErr
	if !errors.As(err, &authErr) {
		t.Fatalf("err = %v, want it to wrap piv.AuthErr", err)
	}

	_, err = signLeaf(t, issuer)
	wantErr(t, err, "the PIN was already rejected, so it is not being tried again")
	if card.pinAttempts != 1 || card.retries != 2 {
		t.Errorf("PIN attempts = %d, retries = %d, want 1 and 2", card.pinAttempts, card.retries)
	}
}

func TestGenerateRoot(t *testing.T) {
	testCases := []struct {
		keyType   certtool.KeyType
		touch     TouchPolicy
		wantAlg   piv.Algorithm
		wantTouch piv.TouchPolicy
	}{
		{certtool.KeyType{Algorithm: "ECDSA", KeyLength: 384}, TouchCached, piv.AlgorithmEC384, piv.TouchPolicyCached},
		{certtool.KeyType{Algorithm: "ECDSA", KeyLength: 256}, TouchAlways, piv.AlgorithmEC256, piv.TouchPolicyAlways},
		{certtool.KeyType{Algorithm: "RSA", KeyLength: 2048}, TouchNever, piv.AlgorithmRSA2048, piv.TouchPolicyNever},
	}
	for _, tc := range testCases {
		t.Run(tc.keyType.Algorithm+string(tc.touch), func(t *testing.T) {
			card := newFakeCard(fakeSerial)
			signs := 0
			token := openFake(t, card, Config{PIN: fakePIN, BeforeSign: func() { signs++ }})

			keyType := tc.keyType
			cert, err := token.GenerateRoot(&certtool.Args{CommonName: "YubiKey Root CA", Validity: time.Hour, KeyType: &keyType}, tc.touch, false)
			if err != nil {
				t.Fatalf("GenerateRoot() err = %v", err)
			}

			if len(card.generated) != 1 {
				t.Fatalf("generated %d keys, want 1", len(card.generated))
			}
			want := piv.Key{Algorithm: tc.wantAlg, PINPolicy: piv.PINPolicyAlways, TouchPolicy: tc.wantTouch}
			if card.generated[0] != want {
				t.Errorf("generated key %+v, want %+v", card.generated[0], want)
			}
			if !cert.IsCA || cert.Subject.CommonName != "YubiKey Root CA" {
				t.Errorf("certificate IsCA = %v, CN = %q, want a CA named YubiKey Root CA", cert.IsCA, cert.Subject.CommonName)
			}
			if err := cert.CheckSignatureFrom(cert); err != nil {
				t.Errorf("root is not self-signed by the YubiKey key: %v", err)
			}
			if stored := card.certs[piv.SlotSignature.Key]; stored == nil || !stored.Equal(cert) {
				t.Error("root certificate was not stored in the slot")
			}
			if signs != 1 {
				t.Errorf("BeforeSign called %d times, want 1", signs)
			}

			// The new root is immediately usable as an issuer.
			issuer, err := token.Issuer()
			if err != nil {
				t.Fatalf("Issuer() after GenerateRoot err = %v", err)
			}
			leaf, err := signLeaf(t, issuer)
			if err != nil {
				t.Fatal(err)
			}
			verifyChain(t, cert, leaf)
		})
	}
}

func TestGenerateRoot_Overwrite(t *testing.T) {
	card := newFakeCard(fakeSerial)
	putRoot(t, card, piv.SlotSignature, nil)
	token := openFake(t, card, pinConfig())

	_, err := token.GenerateRoot(&certtool.Args{CommonName: "New Root CA"}, TouchNever, false)
	wantErr(t, err, tokenPrefix, `the slot already holds the certificate "Fake Root CA"`, "would destroy its key")
	if len(card.generated) != 0 {
		t.Fatal("a key was generated over an occupied slot without overwrite")
	}

	cert, err := token.GenerateRoot(&certtool.Args{CommonName: "New Root CA"}, TouchNever, true)
	if err != nil {
		t.Fatalf("GenerateRoot(overwrite) err = %v", err)
	}
	if card.certs[piv.SlotSignature.Key].Subject.CommonName != "New Root CA" || cert.Subject.CommonName != "New Root CA" {
		t.Error("overwrite did not replace the certificate in the slot")
	}
}

func TestGenerateRoot_Errors(t *testing.T) {
	customKey := make([]byte, 24)
	for i := range customKey {
		customKey[i] = byte(i)
	}

	testCases := []struct {
		name    string
		keyType *certtool.KeyType
		touch   TouchPolicy
		cfg     *Config
		setup   func(*fakeCard)
		want    []string
		// wantKey is whether a key was generated before the failure.
		wantKey bool
	}{
		{
			name:    "unsupported key type",
			keyType: &certtool.KeyType{Algorithm: "ECDSA", KeyLength: 521},
			want:    []string{"key type ECDSA-521 is not supported by YubiKeys"},
		},
		{
			name:  "invalid touch policy",
			touch: "sometimes",
			want:  []string{`YubiKey touch policy "sometimes" is not valid`},
		},
		{
			name:    "RSA-4096 on old firmware",
			keyType: &certtool.KeyType{Algorithm: "RSA", KeyLength: 4096},
			want:    []string{tokenPrefix, "RSA-4096 keys need YubiKey firmware 5.7 or newer"},
		},
		{
			name:    "ECDSA-384 on firmware 3",
			keyType: &certtool.KeyType{Algorithm: "ECDSA", KeyLength: 384},
			touch:   TouchNever,
			setup:   func(c *fakeCard) { c.version = piv.Version{Major: 3, Minor: 4} },
			want:    []string{"(firmware 3.4.0)", "ECDSA-384 keys need YubiKey firmware 4.0 or newer"},
		},
		{
			name:    "touch on firmware 3",
			keyType: &certtool.KeyType{Algorithm: "ECDSA", KeyLength: 256},
			touch:   TouchCached,
			setup:   func(c *fakeCard) { c.version = piv.Version{Major: 3, Minor: 4} },
			want:    []string{"touch policies need YubiKey firmware 4.0 or newer"},
		},
		{
			name:  "slot unreadable",
			setup: func(c *fakeCard) { c.certErr = errors.New("transmit failed") },
			want:  []string{tokenPrefix, "cannot check whether the slot is empty", "transmit failed"},
		},
		{
			name: "management key not hex",
			cfg:  &Config{PIN: fakePIN, ManagementKey: "not hex"},
			want: []string{"YubiKey management key is not valid hex"},
		},
		{
			name: "management key wrong length",
			cfg:  &Config{PIN: fakePIN, ManagementKey: "0102"},
			want: []string{"YubiKey management key is 2 bytes, it must be 16, 24, or 32 bytes"},
		},
		{
			name:  "configured management key rejected",
			cfg:   &Config{PIN: fakePIN, ManagementKey: hex.EncodeToString(customKey)},
			setup: func(c *fakeCard) { c.managementKey = make([]byte, 24) },
			want:  []string{tokenPrefix, "cannot generate a ECDSA-384 key", "the YubiKey rejected the configured management key"},
		},
		{
			name:  "default management key rejected",
			setup: func(c *fakeCard) { c.managementKey = customKey },
			want:  []string{tokenPrefix, "the YubiKey rejected the factory default management key", "provide the management key"},
		},
		{
			name: "metadata needs the right PIN",
			cfg:  &Config{PIN: "654321"},
			want: []string{tokenPrefix, "cannot read the PIN-protected management key", "the PIN is incorrect, 2 attempts remain"},
		},
		{
			name:  "metadata unreadable",
			setup: func(c *fakeCard) { c.metadataErr = errors.New("unmarshal protected metadata: bad tag") },
			want:  []string{tokenPrefix, "cannot read the PIN-protected management key", "bad tag"},
		},
		{
			name: "firmware rejects key generation",
			setup: func(c *fakeCard) {
				c.generateErr = errors.New("smart card error 6a80: incorrect parameter in command data field")
			},
			want: []string{tokenPrefix, "cannot generate a ECDSA-384 key", "firmware may not support the operation"},
		},
		{
			name:    "certificate does not fit",
			setup:   func(c *fakeCard) { c.setCertErr = errors.New("smart card error 6a84: not enough memory") },
			want:    []string{tokenPrefix, "generated a new key but cannot store the root certificate", "rerun with overwrite", "no room left"},
			wantKey: true,
		},
		{
			name:    "touch not given while self-signing",
			setup:   func(c *fakeCard) { c.signErr = errors.New("smart card error 6982: security status not satisfied") },
			want:    []string{tokenPrefix, "generated a new key but cannot self-sign the root certificate", "not touched in time"},
			wantKey: true,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			card := newFakeCard(fakeSerial)
			if tc.setup != nil {
				tc.setup(card)
			}
			cfg := pinConfig()
			if tc.cfg != nil {
				cfg = *tc.cfg
			}
			keyType := tc.keyType
			if keyType == nil {
				keyType = &certtool.KeyType{Algorithm: "ECDSA", KeyLength: 384}
			}
			touch := tc.touch
			if touch == "" {
				touch = TouchCached
			}
			token := openFake(t, card, cfg)

			cert, err := token.GenerateRoot(&certtool.Args{CommonName: "YubiKey Root CA", KeyType: keyType}, touch, false)
			if cert != nil {
				t.Errorf("GenerateRoot() = %v, want nil", cert)
			}
			wantErr(t, err, tc.want...)
			if gotKey := len(card.generated) > 0; gotKey != tc.wantKey {
				t.Errorf("key generated = %v, want %v", gotKey, tc.wantKey)
			}
		})
	}
}

func TestGenerateRoot_ManagementKeySources(t *testing.T) {
	customKey := make([]byte, 24)
	for i := range customKey {
		customKey[i] = byte(0xa0 + i)
	}

	testCases := []struct {
		name       string
		cfg        Config
		setup      func(*fakeCard)
		wantSource string
	}{
		{
			name:       "factory default",
			cfg:        pinConfig(),
			wantSource: managementKeyDefault,
		},
		{
			name: "PIN-protected",
			cfg:  pinConfig(),
			setup: func(c *fakeCard) {
				c.managementKey = customKey
				c.metadata = &piv.Metadata{ManagementKey: &customKey}
			},
			wantSource: managementKeyPINProtected,
		},
		{
			name:       "configured",
			cfg:        Config{PIN: fakePIN, ManagementKey: hex.EncodeToString(customKey)},
			setup:      func(c *fakeCard) { c.managementKey = customKey },
			wantSource: managementKeyConfigured,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			card := newFakeCard(fakeSerial)
			if tc.setup != nil {
				tc.setup(card)
			}
			token := openFake(t, card, tc.cfg)

			if _, err := token.GenerateRoot(&certtool.Args{CommonName: "YubiKey Root CA"}, TouchNever, false); err != nil {
				t.Fatalf("GenerateRoot() err = %v", err)
			}
			if token.managementKeySource != tc.wantSource {
				t.Errorf("management key source = %q, want %q", token.managementKeySource, tc.wantSource)
			}
		})
	}
}

func TestClose_Error(t *testing.T) {
	card := newFakeCard(fakeSerial)
	token := openFake(t, card, Config{})
	card.closeErr = errors.New("disconnect failed")

	wantErr(t, token.Close(), tokenPrefix, "cannot close the YubiKey", "disconnect failed")
}

func TestVerifySignature(t *testing.T) {
	digest := sha256.Sum256([]byte("certtool"))

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherEC, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	pss := &rsa.PSSOptions{Hash: crypto.SHA256, SaltLength: rsa.PSSSaltLengthEqualsHash}
	sign := func(key crypto.Signer, opts crypto.SignerOpts) []byte {
		sig, err := key.Sign(rand.Reader, digest[:], opts)
		if err != nil {
			t.Fatal(err)
		}
		return sig
	}
	pkcs1Sig := sign(rsaKey, crypto.SHA256)
	pssSig := sign(rsaKey, pss)
	ecSig := sign(ecKey, crypto.SHA256)

	testCases := []struct {
		name    string
		pub     crypto.PublicKey
		sig     []byte
		opts    crypto.SignerOpts
		wantErr bool
	}{
		{name: "RSA PKCS1v15", pub: &rsaKey.PublicKey, sig: pkcs1Sig, opts: crypto.SHA256},
		{name: "RSA PSS", pub: &rsaKey.PublicKey, sig: pssSig, opts: pss},
		{name: "RSA wrong padding", pub: &rsaKey.PublicKey, sig: pssSig, opts: crypto.SHA256, wantErr: true},
		{name: "ECDSA", pub: &ecKey.PublicKey, sig: ecSig, opts: crypto.SHA256},
		{name: "ECDSA wrong key", pub: &otherEC.PublicKey, sig: ecSig, opts: crypto.SHA256, wantErr: true},
		{name: "unsupported key", pub: edPub, sig: ecSig, opts: crypto.SHA256, wantErr: true},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := verifySignature(tc.pub, digest[:], tc.sig, tc.opts)
			if (err != nil) != tc.wantErr {
				t.Errorf("verifySignature() err = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

// TestDocumentedScenarios follows docs/use-cases/yubikey-root-ca.md: a root on
// the YubiKey, generated by certtool or already there, signs an intermediate
// CA, whose key file signs server and client leaf certificates.
func TestDocumentedScenarios(t *testing.T) {
	for _, scenario := range []struct {
		name string
		root func(t *testing.T, token *Token, card *fakeCard) *x509.Certificate
	}{
		{
			name: "certtool generates the root",
			root: func(t *testing.T, token *Token, _ *fakeCard) *x509.Certificate {
				cert, err := token.GenerateRoot(&certtool.Args{
					CommonName:   "Acme Root CA",
					Organization: "Acme",
					KeyType:      &certtool.KeyType{Algorithm: "ECDSA", KeyLength: 384},
					Validity:     87600 * time.Hour,
				}, TouchCached, false)
				if err != nil {
					t.Fatalf("GenerateRoot() err = %v", err)
				}
				return cert
			},
		},
		{
			name: "the YubiKey already holds a CA",
			root: func(t *testing.T, _ *Token, card *fakeCard) *x509.Certificate {
				return putRoot(t, card, piv.SlotSignature, nil)
			},
		},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			card := newFakeCard(fakeSerial)
			token := openFake(t, card, pinConfig())
			root := scenario.root(t, token, card)

			// certtool --yubikey --ca --common-name "Acme Issuing CA" ...
			issuer, err := token.Issuer()
			if err != nil {
				t.Fatalf("Issuer() err = %v", err)
			}
			intermediate, err := certtool.GenerateKeyPair(&certtool.Args{
				CA:         true,
				CommonName: "Acme Issuing CA",
				KeyType:    &certtool.KeyType{Algorithm: "ECDSA", KeyLength: 256},
				Validity:   26280 * time.Hour,
				Issuer:     issuer,
			})
			if err != nil {
				t.Fatalf("signing the intermediate CA err = %v", err)
			}
			intermediateCert := parseCertificate(t, intermediate.PublicCertificate)

			// certtool --parent-public-certificate issuing-ca.crt --parent-private-key issuing-ca.key ...
			signs := card.signs
			roots := x509.NewCertPool()
			roots.AddCert(root)
			intermediates := x509.NewCertPool()
			intermediates.AddCert(intermediateCert)
			for _, leaf := range []struct {
				cn    string
				hosts []string
				usage x509.ExtKeyUsage
			}{
				{"api.internal.example.com", []string{"api.internal.example.com", "10.0.0.12"}, x509.ExtKeyUsageServerAuth},
				{"web.internal.example.com", []string{"web.internal.example.com"}, x509.ExtKeyUsageServerAuth},
				{"billing-client", nil, x509.ExtKeyUsageClientAuth},
			} {
				kp, err := certtool.GenerateKeyPair(&certtool.Args{
					CommonName:    leaf.cn,
					Hostnames:     leaf.hosts,
					KeyType:       &certtool.KeyType{Algorithm: "ECDSA", KeyLength: 256},
					Validity:      2160 * time.Hour,
					ParentKeyPair: intermediate,
				})
				if err != nil {
					t.Fatalf("signing %s with the intermediate err = %v", leaf.cn, err)
				}
				cert := parseCertificate(t, kp.PublicCertificate)
				opts := x509.VerifyOptions{Roots: roots, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{leaf.usage}}
				if _, err := cert.Verify(opts); err != nil {
					t.Errorf("%s does not chain to the YubiKey root through the intermediate: %v", leaf.cn, err)
				}
			}
			if card.signs != signs {
				t.Errorf("the YubiKey signed %d leaf certificates, want none", card.signs-signs)
			}
		})
	}
}

func parseCertificate(t *testing.T, data []byte) *x509.Certificate {
	t.Helper()

	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatal("certificate contains no PEM data")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// TestSpecWithYubiKey signs the spec from pkg/certtool/testdata, which the
// docs use as the YubiKey YAML example, with a YubiKey root.
func TestSpecWithYubiKey(t *testing.T) {
	card := newFakeCard(fakeSerial)
	root := putRoot(t, card, piv.SlotSignature, nil)
	token := openFake(t, card, pinConfig())
	issuer, err := token.Issuer()
	if err != nil {
		t.Fatalf("Issuer() err = %v", err)
	}

	specs, err := certtool.ReadSpec(filepath.Join("..", "certtool", "testdata", "yubikey-intermediate.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	results, err := certtool.GenerateFromSpecWithIssuer(specs, t.TempDir(), issuer)
	if err != nil {
		t.Fatalf("GenerateFromSpecWithIssuer() err = %v", err)
	}

	certs := map[string]*x509.Certificate{}
	files := make([]string, 0, len(results))
	for _, r := range results {
		certs[r.CommonName] = parseCertificate(t, r.KeyPair.PublicCertificate)
		files = append(files, filepath.Base(r.CertPath))
	}
	if want := []string{"issuing-ca.crt", "api.crt", "web.crt", "billing-client.crt", "release-sign.crt"}; strings.Join(files, " ") != strings.Join(want, " ") {
		t.Errorf("wrote %q, want %q", files, want)
	}

	roots := x509.NewCertPool()
	roots.AddCert(root)
	intermediates := x509.NewCertPool()
	intermediates.AddCert(certs["Acme Issuing CA"])
	for cn, usage := range map[string]x509.ExtKeyUsage{
		"Acme Issuing CA":          x509.ExtKeyUsageServerAuth,
		"api.internal.example.com": x509.ExtKeyUsageServerAuth,
		"web.internal.example.com": x509.ExtKeyUsageServerAuth,
		"billing-client":           x509.ExtKeyUsageClientAuth,
		"Acme Release Signing":     x509.ExtKeyUsageCodeSigning,
	} {
		opts := x509.VerifyOptions{Roots: roots, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{usage}}
		if _, err := certs[cn].Verify(opts); err != nil {
			t.Errorf("%s does not chain to the YubiKey root: %v", cn, err)
		}
	}
	for _, cn := range []string{"Acme Issuing CA", "Acme Release Signing"} {
		if err := certs[cn].CheckSignatureFrom(root); err != nil {
			t.Errorf("%s is not signed by the YubiKey root: %v", cn, err)
		}
	}
	if card.signs != 2 {
		t.Errorf("the YubiKey signed %d certificates, want the 2 top-level entries", card.signs)
	}
}

// Without a touch policy, a generated root needs a touch for every signature.
func TestGenerateRoot_DefaultTouchPolicy(t *testing.T) {
	card := newFakeCard(fakeSerial)
	token := openFake(t, card, Config{PIN: fakePIN})
	if _, err := token.GenerateRoot(&certtool.Args{CommonName: "YubiKey Root CA", Validity: time.Hour}, "", false); err != nil {
		t.Fatalf("GenerateRoot() err = %v", err)
	}
	if got := card.generated[0].TouchPolicy; got != piv.TouchPolicyAlways {
		t.Errorf("touch policy = %v, want always", got)
	}
	if DefaultTouchPolicy != TouchAlways {
		t.Errorf("DefaultTouchPolicy = %q, want always", DefaultTouchPolicy)
	}
}

// FactoryDefaults reports the default PIN and a default management key, which
// let anyone holding the YubiKey use or replace the root CA key.
func TestFactoryDefaults(t *testing.T) {
	customKey := bytes.Repeat([]byte{0x42}, 24)
	const customPIN = "839201"
	testCases := []struct {
		name  string
		cfg   Config
		setup func(*fakeCard)
		want  []string
	}{
		{name: "factory defaults", cfg: Config{PIN: fakePIN}, want: []string{"PIN", "management key"}},
		{
			name:  "default management key given explicitly",
			cfg:   Config{PIN: customPIN, ManagementKey: hex.EncodeToString(piv.DefaultManagementKey)},
			setup: func(c *fakeCard) { c.pin = customPIN },
			want:  []string{"management key"},
		},
		{
			name: "PIN-protected management key",
			cfg:  Config{PIN: customPIN},
			setup: func(c *fakeCard) {
				c.pin, c.managementKey = customPIN, customKey
				c.metadata = &piv.Metadata{ManagementKey: &customKey}
			},
		},
		{
			name:  "configured management key",
			cfg:   Config{PIN: customPIN, ManagementKey: hex.EncodeToString(customKey)},
			setup: func(c *fakeCard) { c.pin, c.managementKey = customPIN, customKey },
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			card := newFakeCard(fakeSerial)
			if tc.setup != nil {
				tc.setup(card)
			}
			token := openFake(t, card, tc.cfg)
			if _, err := token.GenerateRoot(&certtool.Args{CommonName: "YubiKey Root CA", Validity: time.Hour}, TouchNever, false); err != nil {
				t.Fatalf("GenerateRoot() err = %v", err)
			}
			if diff := cmp.Diff(tc.want, token.FactoryDefaults(), cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("FactoryDefaults() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
