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
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"runtime"
	"strings"
	"time"

	"filippo.io/age"
	"github.com/cloudfra/certtool/pkg/certtool"
	"github.com/go-piv/piv-go/v2/piv"
)

const (
	minPINLength = 6
	maxPINLength = 8

	managementKeyConfigured   = "configured"
	managementKeyPINProtected = "PIN-protected"
	managementKeyDefault      = "factory default"
)

// pivCard is the subset of *piv.YubiKey used by Token, so tests can
// substitute a fake YubiKey.
type pivCard interface {
	Serial() (uint32, error)
	Version() piv.Version
	Certificate(slot piv.Slot) (*x509.Certificate, error)
	KeyInfo(slot piv.Slot) (piv.KeyInfo, error)
	SetCertificate(key []byte, slot piv.Slot, cert *x509.Certificate) error
	GenerateKey(key []byte, slot piv.Slot, opts piv.Key) (crypto.PublicKey, error)
	PrivateKey(slot piv.Slot, public crypto.PublicKey, auth piv.KeyAuth) (crypto.PrivateKey, error)
	Metadata(pin string) (*piv.Metadata, error)
	Close() error
}

// listCards and openCard reach the PC/SC service. Tests replace them.
var (
	listCards = piv.Cards
	openCard  = func(card string) (pivCard, error) {
		yk, err := piv.Open(card)
		if err != nil {
			return nil, err
		}
		return yk, nil
	}
	now = time.Now
)

// Supported reports whether this build can use YubiKeys.
func Supported() bool { return true }

// Token is an open YubiKey. It holds an exclusive connection to the YubiKey
// until Close is called.
type Token struct {
	yk     pivCard
	serial uint32
	slot   piv.Slot
	cfg    Config
	pin    string
	// pinRejected is set once the YubiKey rejects the PIN, so it is never
	// tried again: each wrong attempt brings the PIN closer to being blocked.
	pinRejected bool
	// managementKeySource describes where the management key came from, for
	// error messages.
	managementKeySource string
	// defaultManagementKey is set once the factory default management key
	// has been used.
	defaultManagementKey bool
}

// Open connects to the YubiKey selected by cfg.
func Open(cfg Config) (*Token, error) {
	slot, err := pivSlot(cfg.Slot)
	if err != nil {
		return nil, err
	}

	cards, err := listCards()
	if err != nil {
		return nil, fmt.Errorf("cannot list smart card readers, %s: %w", pcscHint(), err)
	}

	// Find the matching YubiKeys first, then reopen the chosen one, because
	// each open YubiKey holds an exclusive connection.
	type match struct {
		serial uint32
		card   string
	}
	var matches []match
	var others []string
	var serials []string
	var unreadable []error
	for _, card := range cards {
		if !strings.Contains(strings.ToLower(card), "yubikey") {
			others = append(others, card)
			continue
		}
		serial, err := cardSerial(card)
		if err != nil {
			unreadable = append(unreadable, err)
			continue
		}
		serials = append(serials, fmt.Sprint(serial))
		if cfg.Serial == 0 || cfg.Serial == serial {
			matches = append(matches, match{serial: serial, card: card})
		}
	}

	switch {
	case len(unreadable) > 0 && (cfg.Serial == 0 || len(matches) == 0):
		// A YubiKey whose serial number cannot be read might be the one
		// wanted, unless another YubiKey has the requested serial number.
		return nil, errors.Join(unreadable...)
	case len(matches) == 0 && cfg.Serial != 0 && len(serials) > 0:
		return nil, fmt.Errorf("YubiKey with serial number %d is not connected, the connected YubiKeys have serial numbers %s", cfg.Serial, strings.Join(serials, ", "))
	case len(matches) == 0 && len(others) > 0:
		return nil, fmt.Errorf("no YubiKey is connected, the smart card readers found were %q", others)
	case len(matches) == 0:
		return nil, fmt.Errorf("no YubiKey is connected, no smart card readers were found; check that the YubiKey is plugged in and its CCID (smart card) interface is enabled")
	case len(matches) > 1:
		return nil, fmt.Errorf("more than one YubiKey is connected (serial numbers %s), select one by serial number", strings.Join(serials, ", "))
	}

	yk, err := openCard(matches[0].card)
	if err != nil {
		return nil, fmt.Errorf("cannot open YubiKey %d (%q), %s: %w", matches[0].serial, matches[0].card, inUseHint, err)
	}
	return &Token{yk: yk, serial: matches[0].serial, slot: slot, cfg: cfg, pin: cfg.PIN}, nil
}

const inUseHint = "it may be in use by another program such as gpg-agent (scdaemon), ykman, or Yubico Authenticator"

func pcscHint() string {
	switch runtime.GOOS {
	case "windows":
		return "check that the Smart Card service (SCardSvr) is running"
	case "darwin":
		return "check that the YubiKey is plugged in"
	}
	return "check that pcscd is installed and running, for example with `systemctl status pcscd`"
}

func cardSerial(card string) (uint32, error) {
	yk, err := openCard(card)
	if err != nil {
		return 0, fmt.Errorf("cannot open YubiKey %q, %s: %w", card, inUseHint, err)
	}
	serial, err := yk.Serial()
	closeErr := yk.Close()
	if err != nil {
		return 0, fmt.Errorf("cannot read the serial number of YubiKey %q: %w", card, err)
	}
	if closeErr != nil {
		return 0, fmt.Errorf("cannot close YubiKey %q: %w", card, closeErr)
	}
	return serial, nil
}

// Serial returns the serial number of the YubiKey.
func (t *Token) Serial() uint32 {
	return t.serial
}

// Close releases the connection to the YubiKey.
func (t *Token) Close() error {
	if err := t.yk.Close(); err != nil {
		return t.errorf(err, "cannot close the YubiKey")
	}
	return nil
}

// Issuer returns the CA in the configured slot, which signs certificates on
// the YubiKey. The slot must hold a currently valid CA certificate and the
// private key it certifies.
func (t *Token) Issuer() (*certtool.Issuer, error) {
	cert, err := t.yk.Certificate(t.slot)
	if errors.Is(err, piv.ErrNotFound) {
		return nil, t.errorf(err, "there is no certificate in the slot; generate a root CA there first")
	}
	if err != nil {
		return nil, t.errorf(err, "cannot read the certificate")
	}

	cn := cert.Subject.CommonName
	switch {
	case !cert.IsCA:
		return nil, t.errorf(nil, "the certificate %q is not a CA certificate, so it cannot sign other certificates", cn)
	case cert.KeyUsage != 0 && cert.KeyUsage&x509.KeyUsageCertSign == 0:
		return nil, t.errorf(nil, "the certificate %q does not allow certificate signing (key usage cert sign)", cn)
	case now().After(cert.NotAfter):
		return nil, t.errorf(nil, "the certificate %q expired at %s", cn, cert.NotAfter.Format(time.RFC3339))
	case now().Before(cert.NotBefore):
		return nil, t.errorf(nil, "the certificate %q is not valid until %s", cn, cert.NotBefore.Format(time.RFC3339))
	}

	signer, err := t.signer(cert.PublicKey, piv.KeyAuth{})
	if err != nil {
		return nil, err
	}
	return &certtool.Issuer{Certificate: cert, Signer: signer}, nil
}

// GenerateRoot generates a new CA key in the configured slot, self-signs a
// root certificate for it described by args, and stores the certificate in the
// slot. The key is protected by the PIN for every signature and by touchPolicy.
//
// Generating replaces whatever key was in the slot, so GenerateRoot fails if
// the slot already holds a certificate, unless overwrite is true.
func (t *Token) GenerateRoot(args *certtool.Args, touchPolicy TouchPolicy, overwrite bool) (*x509.Certificate, error) {
	keyType := args.GetKeyType()
	algorithm, err := pivAlgorithm(keyType)
	if err != nil {
		return nil, err
	}
	touch, err := pivTouchPolicy(touchPolicy)
	if err != nil {
		return nil, err
	}
	if err := t.checkFirmware(keyType, algorithm, touch); err != nil {
		return nil, err
	}

	if !overwrite {
		existing, err := t.yk.Certificate(t.slot)
		switch {
		case err == nil:
			return nil, t.errorf(nil, "the slot already holds the certificate %q, and generating a root CA would destroy its key; choose another slot or overwrite it explicitly", existing.Subject.CommonName)
		case !errors.Is(err, piv.ErrNotFound):
			return nil, t.errorf(err, "cannot check whether the slot is empty")
		}
	}

	managementKey, err := t.managementKey()
	if err != nil {
		return nil, err
	}

	pub, err := t.yk.GenerateKey(managementKey, t.slot, piv.Key{
		Algorithm:   algorithm,
		PINPolicy:   piv.PINPolicyAlways,
		TouchPolicy: touch,
	})
	if err != nil {
		return nil, t.errorf(err, "cannot generate a %s-%d key", strings.ToUpper(keyType.Algorithm), keyType.KeyLength)
	}

	signer, err := t.signer(pub, piv.KeyAuth{PINPolicy: piv.PINPolicyAlways})
	if err != nil {
		return nil, err
	}

	args.CA = true
	cert, err := certtool.CreateSelfSignedCertificate(args, signer)
	if err != nil {
		return nil, t.errorf(err, "generated a new key but cannot self-sign the root certificate, so the slot now holds a key without a certificate; rerun with overwrite to replace it")
	}

	if err := t.yk.SetCertificate(managementKey, t.slot, cert); err != nil {
		return nil, t.errorf(err, "generated a new key but cannot store the root certificate, so the slot now holds a key without a certificate; rerun with overwrite to replace it")
	}
	return cert, nil
}

// checkFirmware returns an error if the YubiKey firmware is too old for the
// key algorithm or touch policy, before anything is changed on the YubiKey.
func (t *Token) checkFirmware(keyType *certtool.KeyType, algorithm piv.Algorithm, touch piv.TouchPolicy) error {
	v := t.yk.Version()
	switch {
	case (algorithm == piv.AlgorithmRSA3072 || algorithm == piv.AlgorithmRSA4096) && !versionAtLeast(v, 5, 7):
		return t.errorf(nil, "%s-%d keys need YubiKey firmware 5.7 or newer; use ECDSA-384, ECDSA-256, or RSA-2048", strings.ToUpper(keyType.Algorithm), keyType.KeyLength)
	case algorithm == piv.AlgorithmEC384 && !versionAtLeast(v, 4, 0):
		return t.errorf(nil, "ECDSA-384 keys need YubiKey firmware 4.0 or newer; use ECDSA-256 or RSA-2048")
	case touch != piv.TouchPolicyNever && !versionAtLeast(v, 4, 0):
		return t.errorf(nil, "touch policies need YubiKey firmware 4.0 or newer; use the never touch policy")
	}
	return nil
}

func versionAtLeast(v piv.Version, major, minor int) bool {
	return v.Major > major || (v.Major == major && v.Minor >= minor)
}

func (t *Token) signer(pub crypto.PublicKey, auth piv.KeyAuth) (crypto.Signer, error) {
	auth.PINPrompt = t.getPIN
	priv, err := t.yk.PrivateKey(t.slot, pub, auth)
	if err != nil && auth.PINPolicy == 0 {
		// piv-go looks up the key's PIN policy, which fails for keys imported
		// onto firmware older than 5.3. Verifying the PIN before every
		// signature works whatever the policy is.
		auth.PINPolicy = piv.PINPolicyAlways
		priv, err = t.yk.PrivateKey(t.slot, pub, auth)
	}
	if err != nil {
		return nil, t.errorf(err, "cannot use the private key")
	}
	signer, ok := priv.(crypto.Signer)
	if !ok {
		return nil, t.errorf(nil, "the private key of type %T cannot sign", priv)
	}
	return &tokenSigner{token: t, key: signer, pub: pub}, nil
}

// getPIN returns the configured PIN. It never prompts for one.
func (t *Token) getPIN() (string, error) {
	if t.pinRejected {
		return "", t.errorf(nil, "the PIN was already rejected, so it is not being tried again to avoid blocking it")
	}
	if t.pin == "" {
		return "", t.errorf(nil, "a PIN is needed but none was provided")
	}
	if n := len(t.pin); n < minPINLength || n > maxPINLength {
		// Rejecting it here keeps an impossible PIN from using up an attempt.
		t.pinRejected = true
		return "", t.errorf(nil, "the PIN must be %d to %d characters but is %d, so it was not sent to the YubiKey", minPINLength, maxPINLength, n)
	}
	return t.pin, nil
}

// notePINFailure remembers that the YubiKey rejected the PIN.
func (t *Token) notePINFailure(err error) {
	var authErr piv.AuthErr
	if errors.As(err, &authErr) && !isManagementKeyError(err) {
		t.pinRejected = true
	}
}

// managementKey returns the configured management key, else the
// PIN-protected management key stored on the YubiKey, else the default.
func (t *Token) managementKey() ([]byte, error) {
	if t.cfg.ManagementKey != "" {
		t.managementKeySource = managementKeyConfigured
		key, err := hex.DecodeString(strings.TrimSpace(t.cfg.ManagementKey))
		if err != nil {
			return nil, fmt.Errorf("YubiKey management key is not valid hex: %w", err)
		}
		switch len(key) {
		case 16, 24, 32:
		default:
			return nil, fmt.Errorf("YubiKey management key is %d bytes, it must be 16, 24, or 32 bytes (32, 48, or 64 hex digits)", len(key))
		}
		t.defaultManagementKey = bytes.Equal(key, piv.DefaultManagementKey)
		return key, nil
	}

	pin, err := t.getPIN()
	if err != nil {
		return nil, err
	}
	metadata, err := t.yk.Metadata(pin)
	switch {
	case errors.Is(err, piv.ErrNotFound):
		// No PIN-protected management key is stored.
	case err != nil:
		t.notePINFailure(err)
		return nil, t.errorf(err, "cannot read the PIN-protected management key")
	case metadata.ManagementKey != nil:
		t.managementKeySource = managementKeyPINProtected
		return *metadata.ManagementKey, nil
	}
	t.managementKeySource = managementKeyDefault
	t.defaultManagementKey = true
	return piv.DefaultManagementKey, nil
}

// FactoryDefaults returns the factory default credentials in use: "PIN" when
// the configured PIN is the factory default, and "management key" once the
// factory default management key has been used, as GenerateRoot does when no
// other management key is set. Anyone holding the YubiKey can use them, so
// the root CA key is only as safe as the YubiKey itself.
func (t *Token) FactoryDefaults() []string {
	var defaults []string
	if t.pin == piv.DefaultPIN {
		defaults = append(defaults, "PIN")
	}
	if t.defaultManagementKey {
		defaults = append(defaults, "management key")
	}
	return defaults
}

// errorf returns an error that identifies the YubiKey and slot, describes
// what failed, and, when the cause is recognized, says how to fix it. A nil
// err produces an error with no cause.
func (t *Token) errorf(err error, format string, args ...any) error {
	return t.slotErrorf(t.slot, err, format, args...)
}

// slotErrorf is errorf for a slot other than the configured one.
func (t *Token) slotErrorf(slot piv.Slot, err error, format string, args ...any) error {
	v := t.yk.Version()
	prefix := fmt.Sprintf("YubiKey %d (firmware %d.%d.%d), slot %s: ", t.serial, v.Major, v.Minor, v.Patch, slot)
	msg := fmt.Sprintf(format, args...)
	if err == nil {
		return errors.New(prefix + msg)
	}
	if hint := t.hint(err); hint != "" {
		return fmt.Errorf("%s%s: %w; %s", prefix, msg, err, hint)
	}
	return fmt.Errorf("%s%s: %w", prefix, msg, err)
}

func isManagementKeyError(err error) bool {
	return strings.Contains(err.Error(), "authenticating with management key")
}

// hint explains a YubiKey error and how to fix it, or returns "" if the error
// is not recognized.
func (t *Token) hint(err error) string {
	var authErr piv.AuthErr
	msg := err.Error()
	switch {
	case isManagementKeyError(err):
		source := t.managementKeySource
		if source == "" {
			source = "provided"
		}
		return fmt.Sprintf("the YubiKey rejected the %s management key; provide the management key that was set on this YubiKey", source)
	case errors.As(err, &authErr) && (authErr.Retries == 0 || strings.Contains(msg, "blocked")):
		return "the PIN is blocked; unblock it with the PUK, for example with `ykman piv access unblock-pin`"
	case errors.As(err, &authErr):
		attempts := "attempts remain"
		if authErr.Retries == 1 {
			attempts = "attempt remains"
		}
		return fmt.Sprintf("the PIN is incorrect, %d %s before it is blocked", authErr.Retries, attempts)
	case strings.Contains(msg, "security status not satisfied"):
		return "the YubiKey refused because the PIN was not verified or the YubiKey was not touched in time; touch the YubiKey when it blinks"
	case strings.Contains(msg, "not enough memory"):
		return "the YubiKey has no room left for this object"
	case strings.Contains(msg, "function not supported"), strings.Contains(msg, "incorrect parameter"):
		return "this YubiKey's firmware may not support the operation"
	}
	return ""
}

// tokenSigner signs with a YubiKey key. It reports each signature to
// Config.BeforeSign, adds YubiKey context to errors, and checks every
// signature against the expected public key.
type tokenSigner struct {
	token *Token
	key   crypto.Signer
	pub   crypto.PublicKey
}

func (s *tokenSigner) Public() crypto.PublicKey {
	return s.pub
}

func (s *tokenSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if s.token.cfg.BeforeSign != nil {
		s.token.cfg.BeforeSign()
	}
	sig, err := s.key.Sign(rand, digest, opts)
	if err != nil {
		s.token.notePINFailure(err)
		return nil, s.token.errorf(err, "cannot sign")
	}
	if err := verifySignature(s.pub, digest, sig, opts); err != nil {
		return nil, s.token.errorf(err, "the private key in the slot does not match the certificate stored there; the key was probably replaced without updating the certificate")
	}
	return sig, nil
}

func verifySignature(pub crypto.PublicKey, digest []byte, sig []byte, opts crypto.SignerOpts) error {
	switch pub := pub.(type) {
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(pub, digest, sig) {
			return errors.New("ECDSA signature does not verify")
		}
		return nil
	case *rsa.PublicKey:
		if pss, ok := opts.(*rsa.PSSOptions); ok {
			return rsa.VerifyPSS(pub, pss.Hash, digest, sig, pss)
		}
		return rsa.VerifyPKCS1v15(pub, opts.HashFunc(), digest, sig)
	}
	return fmt.Errorf("cannot verify signatures for key type %T", pub)
}

func pivSlot(s string) (piv.Slot, error) {
	key, err := parseSlotKey(s)
	if err != nil {
		return piv.Slot{}, err
	}
	switch key {
	case piv.SlotAuthentication.Key:
		return piv.SlotAuthentication, nil
	case piv.SlotSignature.Key:
		return piv.SlotSignature, nil
	case piv.SlotKeyManagement.Key:
		return piv.SlotKeyManagement, nil
	case piv.SlotCardAuthentication.Key:
		return piv.SlotCardAuthentication, nil
	}
	if slot, ok := piv.RetiredKeyManagementSlot(key); ok {
		return slot, nil
	}
	return piv.Slot{}, fmt.Errorf("YubiKey slot %q is not a PIV key slot, must be 9a, 9c, 9d, 9e, or 82 through 95", s)
}

func pivAlgorithm(keyType *certtool.KeyType) (piv.Algorithm, error) {
	switch fmt.Sprintf("%s-%d", strings.ToUpper(keyType.Algorithm), keyType.KeyLength) {
	case "ECDSA-256":
		return piv.AlgorithmEC256, nil
	case "ECDSA-384":
		return piv.AlgorithmEC384, nil
	case "RSA-2048":
		return piv.AlgorithmRSA2048, nil
	case "RSA-4096":
		return piv.AlgorithmRSA4096, nil
	}
	return 0, fmt.Errorf("key type %s-%d is not supported by YubiKeys, must be ECDSA-256, ECDSA-384, RSA-2048, or RSA-4096", keyType.Algorithm, keyType.KeyLength)
}

func pivTouchPolicy(p TouchPolicy) (piv.TouchPolicy, error) {
	switch p {
	case TouchNever:
		return piv.TouchPolicyNever, nil
	case TouchAlways, "":
		return piv.TouchPolicyAlways, nil
	case TouchCached:
		return piv.TouchPolicyCached, nil
	}
	return 0, fmt.Errorf("YubiKey touch policy %q is not valid, must be never, always, or cached", p)
}

// ageSlots are the slots searched for age keys: the retired key management
// slots that age-plugin-yubikey uses, then the key management slot.
var ageSlots = []uint32{0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x9d}

// AgeIdentities returns an age identity for each P-256 key in the slots that
// age-plugin-yubikey uses (82 through 95) and the key management slot 9d. They
// decrypt files encrypted to the key's age1yubikey or age1tag recipient, using
// the PIN and, if the key's touch policy needs one, a touch.
func (t *Token) AgeIdentities() ([]age.Identity, error) {
	var identities []age.Identity
	for _, key := range ageSlots {
		slot, ok := piv.RetiredKeyManagementSlot(key)
		if !ok {
			slot = piv.SlotKeyManagement
		}
		pub := t.slotPublicKey(slot)
		ecPub, ok := pub.(*ecdsa.PublicKey)
		if !ok || ecPub.Curve != elliptic.P256() {
			continue
		}
		ecdhPub, err := ecPub.ECDH()
		if err != nil {
			continue
		}
		identity, err := certtool.NewP256Identity(&slotKeyExchanger{token: t, slot: slot, pub: ecPub, ecdhPub: ecdhPub})
		if err != nil {
			return nil, err
		}
		identities = append(identities, identity)
	}
	if len(identities) == 0 {
		return nil, fmt.Errorf("YubiKey %d: no slot from 82 to 95 or 9d holds a P-256 key to decrypt with; create one with age-plugin-yubikey --generate", t.serial)
	}
	return identities, nil
}

// slotPublicKey returns the public key in slot, or nil. It asks the key's
// metadata, which firmware 5.3 and later have, then the slot's certificate.
func (t *Token) slotPublicKey(slot piv.Slot) crypto.PublicKey {
	if info, err := t.yk.KeyInfo(slot); err == nil && info.PublicKey != nil {
		return info.PublicKey
	}
	if cert, err := t.yk.Certificate(slot); err == nil {
		return cert.PublicKey
	}
	return nil
}

// slotKeyExchanger computes ECDH with the P-256 key in a slot.
type slotKeyExchanger struct {
	token   *Token
	slot    piv.Slot
	pub     *ecdsa.PublicKey
	ecdhPub *ecdh.PublicKey
}

func (k *slotKeyExchanger) PublicKey() *ecdh.PublicKey { return k.ecdhPub }

func (k *slotKeyExchanger) Curve() ecdh.Curve { return ecdh.P256() }

func (k *slotKeyExchanger) ECDH(peer *ecdh.PublicKey) ([]byte, error) {
	t := k.token
	auth := piv.KeyAuth{PINPrompt: t.getPIN}
	priv, err := t.yk.PrivateKey(k.slot, k.pub, auth)
	if err != nil {
		// As in signer, keys imported onto older firmware have no PIN policy
		// to look up, so verify the PIN first.
		auth.PINPolicy = piv.PINPolicyAlways
		priv, err = t.yk.PrivateKey(k.slot, k.pub, auth)
	}
	if err != nil {
		return nil, t.slotErrorf(k.slot, err, "cannot use the age key")
	}
	exchanger, ok := priv.(interface {
		ECDH(*ecdh.PublicKey) ([]byte, error)
	})
	if !ok {
		return nil, t.slotErrorf(k.slot, nil, "the key of type %T cannot decrypt", priv)
	}
	if t.cfg.BeforeDecrypt != nil {
		t.cfg.BeforeDecrypt()
	}
	shared, err := exchanger.ECDH(peer)
	if err != nil {
		t.notePINFailure(err)
		return nil, t.slotErrorf(k.slot, err, "cannot decrypt")
	}
	return shared, nil
}
