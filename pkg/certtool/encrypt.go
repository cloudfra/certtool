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
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"
	"filippo.io/age/armor"
	"filippo.io/age/plugin"
	"filippo.io/age/tag"
	"filippo.io/hpke"
	"filippo.io/nistec"
	"golang.org/x/crypto/chacha20poly1305"

	"github.com/cloudfra/certtool/internal/safefile"
)

// EncryptedSuffix is added to the name of a private key or .pfx file that is
// encrypted with age.
const EncryptedSuffix = ".age"

// ErrNoAgeIdentity is returned when a file is encrypted with age and no
// identity was given to decrypt it.
var ErrNoAgeIdentity = errors.New("no identity to decrypt it was given")

// KeyEncryption encrypts the private key and .pfx files certtool writes, and
// decrypts the encrypted private keys it reads. A nil *KeyEncryption writes
// and reads plain files.
type KeyEncryption struct {
	// Recipients, when not empty, encrypts every private key and .pfx file
	// written to all of them. The file name gets EncryptedSuffix.
	Recipients []age.Recipient
	// Identities decrypt encrypted private keys that are read, such as a
	// parent CA's key or a key a spec reuses.
	Identities []age.Identity
}

// Encrypts reports whether e encrypts the files it writes.
func (e *KeyEncryption) Encrypts() bool {
	return e != nil && len(e.Recipients) > 0
}

// path returns the name a private file is written to.
func (e *KeyEncryption) path(path string) string {
	if e.Encrypts() {
		return path + EncryptedSuffix
	}
	return path
}

// writePrivate writes data to path, encrypted when e has recipients, and
// returns the path written.
func (e *KeyEncryption) writePrivate(path string, data []byte) (string, error) {
	if e.Encrypts() {
		var err error
		if data, err = EncryptPrivateData(data, e.Recipients); err != nil {
			return "", fmt.Errorf("cannot encrypt %s: %w", path, err)
		}
	}
	path = e.path(path)
	return path, safefile.WritePrivate(path, data)
}

// WriteKeyPair writes the certificate to certFile and the private key to
// keyFile, or to keyFile with EncryptedSuffix when e encrypts. It returns the
// path of the key file.
func (e *KeyEncryption) WriteKeyPair(kp *KeyPair, certFile, keyFile string) (string, error) {
	if err := safefile.WritePublic(certFile, kp.PublicCertificate); err != nil {
		return "", err
	}
	return e.writePrivate(keyFile, kp.PrivateKey)
}

// WritePFX writes the PKCS#12 bundle of kp to pfxFile, or to pfxFile with
// EncryptedSuffix when e encrypts, and returns the path written.
func (e *KeyEncryption) WritePFX(kp *KeyPair, pfxFile string) (string, error) {
	if len(kp.PFX) == 0 {
		return "", errors.New("no PKCS#12 data to write")
	}
	return e.writePrivate(pfxFile, kp.PFX)
}

// ReadPrivateFile reads a private key or .pfx file, decrypting it with e's
// identities when it is encrypted with age.
func (e *KeyEncryption) ReadPrivateFile(path string) ([]byte, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	if !IsAgeEncrypted(data) {
		return data, nil
	}
	if e == nil || len(e.Identities) == 0 {
		return nil, fmt.Errorf("%s is encrypted with age, and %w", path, ErrNoAgeIdentity)
	}
	plain, err := DecryptPrivateData(data, e.Identities)
	if err != nil {
		return nil, fmt.Errorf("cannot decrypt %s: %w", path, err)
	}
	return plain, nil
}

// ReadKeyPairFromFile reads a certificate and its private key like the
// package function ReadKeyPairFromFile, decrypting the key with e's
// identities when it is encrypted with age.
func (e *KeyEncryption) ReadKeyPairFromFile(publicCertificateFile, privateKeyFile string) (*KeyPair, error) {
	if publicCertificateFile == "" && privateKeyFile == "" {
		return nil, errors.New("public certificate and private key were not provided")
	}
	if publicCertificateFile != "" && privateKeyFile == "" {
		return nil, errors.New("public certificate was provided without a private key")
	}
	if publicCertificateFile == "" && privateKeyFile != "" {
		return nil, errors.New("private key was provided without a public certificate")
	}

	pub, err := os.ReadFile(filepath.Clean(publicCertificateFile))
	if err != nil {
		return nil, fmt.Errorf("cannot read the public certificate file (%s), %w", publicCertificateFile, err)
	}
	priv, err := e.ReadPrivateFile(privateKeyFile)
	if err != nil {
		return nil, fmt.Errorf("cannot read the private key file (%s), %w", privateKeyFile, err)
	}
	return &KeyPair{PublicCertificate: pub, PrivateKey: priv}, nil
}

// existingPrivateFile returns path, or path with EncryptedSuffix, whichever
// exists, or "" when neither does.
func existingPrivateFile(path string) (string, error) {
	plain, encrypted := fileExists(path), fileExists(path+EncryptedSuffix)
	switch {
	case plain && encrypted:
		return "", fmt.Errorf("%w: both %s and %s exist; delete the one that is out of date", ErrExistingFiles, path, path+EncryptedSuffix)
	case encrypted:
		return path + EncryptedSuffix, nil
	case plain:
		return path, nil
	}
	return "", nil
}

// IsAgeEncrypted reports whether data is an age encrypted file, armored or
// binary.
func IsAgeEncrypted(data []byte) bool {
	data = bytes.TrimLeft(data, " \t\r\n")
	return bytes.HasPrefix(data, []byte(armor.Header)) || bytes.HasPrefix(data, []byte("age-encryption.org/"))
}

// EncryptPrivateData encrypts data to recipients as an armored age file.
func EncryptPrivateData(data []byte, recipients []age.Recipient) ([]byte, error) {
	var buf bytes.Buffer
	aw := armor.NewWriter(&buf)
	w, err := age.Encrypt(aw, recipients...)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(data); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	if err := aw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// DecryptPrivateData decrypts an armored or binary age file with any of
// identities.
func DecryptPrivateData(data []byte, identities []age.Identity) ([]byte, error) {
	var src io.Reader = bytes.NewReader(data)
	if bytes.HasPrefix(bytes.TrimLeft(data, " \t\r\n"), []byte(armor.Header)) {
		src = armor.NewReader(bytes.NewReader(bytes.TrimLeft(data, " \t\r\n")))
	}
	r, err := age.Decrypt(src, identities...)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(r)
}

// ParseAgeRecipient parses an age recipient: an X25519 recipient (age1...),
// a post-quantum hybrid recipient (age1pq1...), a tagged recipient for a
// hardware key (age1tag1..., age1tagpq1...), or an age-plugin-yubikey
// recipient (age1yubikey1...). Encrypting to these needs no plugin.
func ParseAgeRecipient(s string) (age.Recipient, error) {
	s = strings.TrimSpace(s)
	switch {
	case strings.HasPrefix(s, "age1tag1"), strings.HasPrefix(s, "age1tagpq1"):
		return tag.ParseRecipient(s)
	case strings.HasPrefix(s, "age1pq1"):
		return age.ParseHybridRecipient(s)
	case strings.HasPrefix(s, "age1yubikey1"):
		_, data, err := plugin.ParseRecipient(s)
		if err != nil {
			return nil, fmt.Errorf("malformed recipient %q: %w", s, err)
		}
		return newPIVP256Recipient(data)
	}
	r, err := age.ParseX25519Recipient(s)
	if err == nil {
		return r, nil
	}
	if name, _, perr := plugin.ParseRecipient(s); perr == nil {
		return nil, fmt.Errorf("recipient %q needs the age-plugin-%s plugin, which certtool cannot run; use an age1, age1pq1, age1tag1, or age1yubikey1 recipient", s, name)
	}
	return nil, fmt.Errorf("%q is not an age recipient such as age1... or age1yubikey1...: %w", s, err)
}

// pivP256 is the stanza type and HKDF label of age-plugin-yubikey's
// recipients.
const pivP256 = "piv-p256"

// p256tagLabel is the HPKE info of tagged P-256 recipients.
const p256tagLabel = "age-encryption.org/p256tag"

// pivP256Recipient is an age-plugin-yubikey recipient (age1yubikey1...): a
// P-256 key in a YubiKey PIV slot. Files are encrypted to it with ephemeral
// ECDH, HKDF-SHA256, and ChaCha20-Poly1305, exactly as the plugin does.
type pivP256Recipient struct {
	pub *ecdh.PublicKey
	// compressed is the compressed SEC 1 encoding of pub.
	compressed []byte
}

func newPIVP256Recipient(compressed []byte) (*pivP256Recipient, error) {
	if len(compressed) != 33 {
		return nil, errors.New("invalid age1yubikey recipient: not a compressed P-256 point")
	}
	p, err := nistec.NewP256Point().SetBytes(compressed)
	if err != nil {
		return nil, fmt.Errorf("invalid age1yubikey recipient: %w", err)
	}
	pub, err := ecdh.P256().NewPublicKey(p.Bytes())
	if err != nil {
		return nil, fmt.Errorf("invalid age1yubikey recipient: %w", err)
	}
	return &pivP256Recipient{pub: pub, compressed: compressed}, nil
}

// pivP256Tag identifies the recipient of a stanza: the first four bytes of
// the SHA-256 of its compressed public key.
func pivP256Tag(compressed []byte) []byte {
	sum := sha256.Sum256(compressed)
	return sum[:4]
}

// pivP256Key derives the key that wraps the file key.
func pivP256Key(sharedSecret, epk, recipient []byte) ([]byte, error) {
	salt := append(append([]byte{}, epk...), recipient...)
	return hkdf.Key(sha256.New, sharedSecret, salt, pivP256, chacha20poly1305.KeySize)
}

// compress returns the compressed SEC 1 encoding of a P-256 public key.
func compress(pub *ecdh.PublicKey) []byte {
	p, err := nistec.NewP256Point().SetBytes(pub.Bytes())
	if err != nil {
		panic("internal error: invalid P-256 public key")
	}
	return p.BytesCompressed()
}

func (r *pivP256Recipient) Wrap(fileKey []byte) ([]*age.Stanza, error) {
	esk, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	shared, err := esk.ECDH(r.pub)
	if err != nil {
		return nil, err
	}
	epk := compress(esk.PublicKey())
	key, err := pivP256Key(shared, epk, r.compressed)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	return []*age.Stanza{{
		Type: pivP256,
		Args: []string{base64.RawStdEncoding.EncodeToString(pivP256Tag(r.compressed)), base64.RawStdEncoding.EncodeToString(epk)},
		Body: aead.Seal(nil, make([]byte, chacha20poly1305.NonceSize), fileKey, nil),
	}}, nil
}

// p256Identity decrypts files encrypted to the age1yubikey or age1tag
// recipient of a P-256 key, using the key only for ECDH.
type p256Identity struct {
	key        ecdh.KeyExchanger
	compressed []byte
	tagged     *tag.Recipient
}

// NewP256Identity returns an age identity that decrypts files encrypted to
// the age1yubikey (age-plugin-yubikey) or age1tag recipient of key. key only
// needs to compute ECDH, so it can be held by hardware such as a YubiKey.
func NewP256Identity(key ecdh.KeyExchanger) (age.Identity, error) {
	if key.Curve() != ecdh.P256() {
		return nil, errors.New("age YubiKey identities need a P-256 key")
	}
	compressed := compress(key.PublicKey())
	tagged, err := tag.NewClassicRecipient(compressed)
	if err != nil {
		return nil, err
	}
	return &p256Identity{key: key, compressed: compressed, tagged: tagged}, nil
}

func (i *p256Identity) Unwrap(stanzas []*age.Stanza) ([]byte, error) {
	for _, s := range stanzas {
		var fileKey []byte
		var err error
		switch s.Type {
		case pivP256:
			fileKey, err = i.unwrapPIVP256(s)
		case "p256tag":
			fileKey, err = i.unwrapP256Tag(s)
		default:
			continue
		}
		if errors.Is(err, age.ErrIncorrectIdentity) {
			continue
		}
		return fileKey, err
	}
	return nil, age.ErrIncorrectIdentity
}

// stanzaArgs decodes the two base64 arguments of a stanza: a 4-byte tag and
// an ephemeral public key.
func stanzaArgs(s *age.Stanza) (stanzaTag, epk []byte, err error) {
	if len(s.Args) != 2 {
		return nil, nil, fmt.Errorf("invalid %s stanza", s.Type)
	}
	if stanzaTag, err = base64.RawStdEncoding.DecodeString(s.Args[0]); err != nil || len(stanzaTag) != 4 {
		return nil, nil, fmt.Errorf("invalid %s stanza tag", s.Type)
	}
	if epk, err = base64.RawStdEncoding.DecodeString(s.Args[1]); err != nil {
		return nil, nil, fmt.Errorf("invalid %s stanza key", s.Type)
	}
	return stanzaTag, epk, nil
}

func (i *p256Identity) unwrapPIVP256(s *age.Stanza) ([]byte, error) {
	stanzaTag, epk, err := stanzaArgs(s)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(stanzaTag, pivP256Tag(i.compressed)) {
		return nil, age.ErrIncorrectIdentity
	}
	peer, err := newPIVP256Recipient(epk)
	if err != nil {
		return nil, fmt.Errorf("invalid %s stanza key: %w", pivP256, err)
	}
	shared, err := i.key.ECDH(peer.pub)
	if err != nil {
		return nil, err
	}
	key, err := pivP256Key(shared, epk, i.compressed)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	fileKey, err := aead.Open(nil, make([]byte, chacha20poly1305.NonceSize), s.Body, nil)
	if err != nil {
		return nil, fmt.Errorf("cannot decrypt the %s file key: %w", pivP256, err)
	}
	return fileKey, nil
}

func (i *p256Identity) unwrapP256Tag(s *age.Stanza) ([]byte, error) {
	stanzaTag, enc, err := stanzaArgs(s)
	if err != nil {
		return nil, err
	}
	want, err := i.tagged.Tag(enc)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(stanzaTag, want) {
		return nil, age.ErrIncorrectIdentity
	}
	priv, err := hpke.NewDHKEMPrivateKey(i.key)
	if err != nil {
		return nil, err
	}
	r, err := hpke.NewRecipient(enc, priv, hpke.HKDFSHA256(), hpke.ChaCha20Poly1305(), []byte(p256tagLabel))
	if err != nil {
		return nil, fmt.Errorf("cannot decrypt the p256tag file key: %w", err)
	}
	fileKey, err := r.Open(nil, s.Body)
	if err != nil {
		return nil, fmt.Errorf("cannot decrypt the p256tag file key: %w", err)
	}
	return fileKey, nil
}

// removeOtherForm removes the encrypted form of a private file when e writes
// it plain, or the plain form when e encrypts, so that regenerating never
// leaves a stale key next to the new one.
func removeOtherForm(path string, e *KeyEncryption) error {
	other := path + EncryptedSuffix
	if e.Encrypts() {
		other = path
	}
	if err := os.Remove(other); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("cannot remove %s: %w", other, err)
	}
	return nil
}
