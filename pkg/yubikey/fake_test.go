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
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"testing"
	"time"

	"github.com/go-piv/piv-go/v2/piv"
)

const (
	fakePIN    = "123456"
	fakeSerial = 1234567
)

// fakeCard is an in-memory YubiKey that behaves like piv-go's *piv.YubiKey
// closely enough to exercise Token: it checks the PIN with a retry counter,
// checks the management key, and stores keys and certificates per slot.
type fakeCard struct {
	serial    uint32
	serialErr error
	version   piv.Version

	pin           string
	retries       int
	pinAttempts   int
	managementKey []byte
	metadata      *piv.Metadata
	metadataErr   error

	certs map[uint32]*x509.Certificate
	keys  map[uint32]crypto.Signer

	openErr     error
	certErr     error
	generateErr error
	setCertErr  error
	signErr     error
	closeErr    error

	generated []piv.Key
	signs     int
	opens     int
	closes    int
}

func newFakeCard(serial uint32) *fakeCard {
	return &fakeCard{
		serial:        serial,
		version:       piv.Version{Major: 5, Minor: 4, Patch: 3},
		pin:           fakePIN,
		retries:       3,
		managementKey: piv.DefaultManagementKey,
		certs:         map[uint32]*x509.Certificate{},
		keys:          map[uint32]crypto.Signer{},
	}
}

func (c *fakeCard) Serial() (uint32, error) { return c.serial, c.serialErr }

func (c *fakeCard) Version() piv.Version { return c.version }

func (c *fakeCard) Close() error {
	c.closes++
	return c.closeErr
}

func (c *fakeCard) checkManagementKey(key []byte) error {
	if !bytes.Equal(key, c.managementKey) {
		return fmt.Errorf("authenticating with management key: %w", piv.AuthErr{})
	}
	return nil
}

// verifyPIN mimics the PIV applet: a blocked PIN fails without counting, a
// wrong PIN uses up an attempt.
func (c *fakeCard) verifyPIN(pin string) error {
	c.pinAttempts++
	if c.retries == 0 {
		return fmt.Errorf("smart card error 6983: authentication method blocked: %w", piv.AuthErr{})
	}
	if pin != c.pin {
		c.retries--
		return fmt.Errorf("verify pin: %w", piv.AuthErr{Retries: c.retries})
	}
	return nil
}

func (c *fakeCard) Certificate(slot piv.Slot) (*x509.Certificate, error) {
	if c.certErr != nil {
		return nil, c.certErr
	}
	cert, ok := c.certs[slot.Key]
	if !ok {
		return nil, fmt.Errorf("command failed: %w", piv.ErrNotFound)
	}
	return cert, nil
}

func (c *fakeCard) SetCertificate(key []byte, slot piv.Slot, cert *x509.Certificate) error {
	if err := c.checkManagementKey(key); err != nil {
		return err
	}
	if c.setCertErr != nil {
		return c.setCertErr
	}
	c.certs[slot.Key] = cert
	return nil
}

func (c *fakeCard) GenerateKey(key []byte, slot piv.Slot, opts piv.Key) (crypto.PublicKey, error) {
	if err := c.checkManagementKey(key); err != nil {
		return nil, err
	}
	if c.generateErr != nil {
		return nil, c.generateErr
	}

	var signer crypto.Signer
	var err error
	switch opts.Algorithm {
	case piv.AlgorithmEC256:
		signer, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case piv.AlgorithmEC384:
		signer, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case piv.AlgorithmRSA2048, piv.AlgorithmRSA4096:
		// A real RSA-4096 key is slow to generate and behaves the same here.
		signer, err = rsa.GenerateKey(rand.Reader, 2048)
	default:
		return nil, fmt.Errorf("fake YubiKey does not support algorithm %v", opts.Algorithm)
	}
	if err != nil {
		return nil, err
	}

	c.generated = append(c.generated, opts)
	c.keys[slot.Key] = signer
	return signer.Public(), nil
}

func (c *fakeCard) PrivateKey(slot piv.Slot, _ crypto.PublicKey, auth piv.KeyAuth) (crypto.PrivateKey, error) {
	key, ok := c.keys[slot.Key]
	if !ok {
		return nil, fmt.Errorf("command failed: %w", piv.ErrNotFound)
	}
	return &fakeKey{card: c, key: key, auth: auth}, nil
}

func (c *fakeCard) Metadata(pin string) (*piv.Metadata, error) {
	if err := c.verifyPIN(pin); err != nil {
		return nil, fmt.Errorf("authenticating with pin: %w", err)
	}
	if c.metadataErr != nil {
		return nil, c.metadataErr
	}
	if c.metadata == nil {
		return nil, fmt.Errorf("command failed: %w", piv.ErrNotFound)
	}
	return c.metadata, nil
}

// fakeKey is a slot key that needs the PIN for every signature, like a key
// generated with PINPolicyAlways.
type fakeKey struct {
	card *fakeCard
	key  crypto.Signer
	auth piv.KeyAuth
}

func (k *fakeKey) Public() crypto.PublicKey { return k.key.Public() }

func (k *fakeKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if k.card.signErr != nil {
		return nil, k.card.signErr
	}
	pin := k.auth.PIN
	if pin == "" {
		if k.auth.PINPrompt == nil {
			return nil, fmt.Errorf("pin required but wasn't provided")
		}
		var err error
		if pin, err = k.auth.PINPrompt(); err != nil {
			return nil, err
		}
	}
	if err := k.card.verifyPIN(pin); err != nil {
		return nil, err
	}
	k.card.signs++
	return k.key.Sign(rand, digest, opts)
}

// installFakes routes Open to the given readers. Readers without a fake card
// are smart card readers that are not YubiKeys.
func installFakes(t *testing.T, readers []string, cards map[string]*fakeCard, listErr error) {
	t.Helper()

	oldList, oldOpen := listCards, openCard
	t.Cleanup(func() { listCards, openCard = oldList, oldOpen })

	listCards = func() ([]string, error) { return readers, listErr }
	openCard = func(reader string) (pivCard, error) {
		card, ok := cards[reader]
		if !ok {
			return nil, fmt.Errorf("unknown reader %q", reader)
		}
		if card.openErr != nil {
			return nil, card.openErr
		}
		card.opens++
		return card, nil
	}
}

// openFake opens a Token on a single fake YubiKey.
func openFake(t *testing.T, card *fakeCard, cfg Config) *Token {
	t.Helper()

	reader := "Yubico YubiKey OTP+FIDO+CCID 00 00"
	installFakes(t, []string{reader}, map[string]*fakeCard{reader: card}, nil)
	token, err := Open(cfg)
	if err != nil {
		t.Fatalf("Open() err = %v", err)
	}
	return token
}

// putRoot stores a CA certificate and its key in a slot of card. mutate may
// change the certificate template before it is signed.
func putRoot(t *testing.T, card *fakeCard, slot piv.Slot, mutate func(*x509.Certificate)) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Fake Root CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	if mutate != nil {
		mutate(template)
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	card.certs[slot.Key] = cert
	card.keys[slot.Key] = key
	return cert
}
