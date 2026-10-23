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

package certtool

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"software.sslmate.com/src/go-pkcs12"
)

const (
	secretMessage      = "this is a secret message"
	testLoopbackIP     = "127.0.0.1"
	testOrgValue       = "organization"
	testPubCertFile    = "pub.crt"
	testPrivKeyFile    = "priv.key"
	testLocalhost      = "localhost"
	testCloudfra       = "cloudfra"
	testExampleCom     = "example.com"
	testDupHostPort    = "dup.com:80"
	testMixHostPort    = "mix.com:80"
	testLoopbackIPPort = "192.168.1.1:443"
)

var testHostnames = []string{"a.com", "b.com", testLoopbackIP}

func TestPublicKey(t *testing.T) {
	if testing.Short() {
		t.Skip("certificate generation takes a long time")
	}

	pk, err := publicKey(&Args{})
	if pk != nil {
		t.Errorf("publicKey(&Args{}) = %v, want nil", pk)
	}
	if err == nil {
		t.Error("publicKey(&Args{}) err = nil, want error")
	}

	pk, err = publicKey(&rsa.PrivateKey{})
	if pk == nil {
		t.Error("publicKey(&rsa.PrivateKey{}) = nil, want non-nil")
	}
	if err != nil {
		t.Errorf("publicKey(&rsa.PrivateKey{}) err = %v, want nil", err)
	}

	pk, err = publicKey(&ecdsa.PrivateKey{})
	if pk == nil {
		t.Error("publicKey(&ecdsa.PrivateKey{}) = nil, want non-nil")
	}
	if err != nil {
		t.Errorf("publicKey(&ecdsa.PrivateKey{}) err = %v, want nil", err)
	}
}

func TestReadKeyPairFromFile_Errors(t *testing.T) {
	tmpDir := mustTemp(t)
	pubPath := filepath.Join(tmpDir, testPubCertFile)
	privPath := filepath.Join(tmpDir, testPrivKeyFile)
	originalKP, err := GenerateAndWriteKeyPair(&Args{}, pubPath, privPath)
	if err != nil {
		t.Fatal(err)
	}

	testCases := []struct {
		publicCertificateFile string
		privateKeyFile        string
		wantErr               string
	}{
		{
			publicCertificateFile: "",
			privateKeyFile:        "",
			wantErr:               "public certificate and private key were not provided",
		},
		{
			publicCertificateFile: pubPath,
			privateKeyFile:        "",
			wantErr:               "public certificate was provided without a private key",
		},
		{
			publicCertificateFile: "",
			privateKeyFile:        privPath,
			wantErr:               "private key was provided without a public certificate",
		},
		{
			publicCertificateFile: pubPath,
			privateKeyFile:        "does-not-exist",
			wantErr:               "cannot read the private key file (does-not-exist), open does-not-exist:",
		},
		{
			publicCertificateFile: "does-not-exist",
			privateKeyFile:        privPath,
			wantErr:               "cannot read the public certificate file (does-not-exist), open does-not-exist:",
		},
		{
			publicCertificateFile: pubPath,
			privateKeyFile:        privPath,
			wantErr:               "",
		},
	}
	for _, tc := range testCases {
		tc := tc
		t.Run(fmt.Sprintf("%v", tc), func(t *testing.T) {
			t.Parallel()
			kp, err := ReadKeyPairFromFile(tc.publicCertificateFile, tc.privateKeyFile)
			if tc.wantErr == "" {
				if err != nil {
					t.Error(err)
				}
				if kp == nil {
					t.Fatal("KeyPair is nil")
				}
				if string(kp.PublicCertificate) != string(originalKP.PublicCertificate) {
					t.Errorf("original and read public certificates do not match.\ngot: %s\nwant: %s", string(kp.PublicCertificate), string(originalKP.PublicCertificate))
				}
				if string(kp.PrivateKey) != string(originalKP.PrivateKey) {
					t.Errorf("original and read private key do not match.\ngot: %s\nwant: %s", string(kp.PrivateKey), string(originalKP.PrivateKey))
				}
			} else {
				if kp != nil {
					t.Error("key pair is not nil")
				}

				if err == nil {
					t.Fatalf("error is nil, want: '%s'", tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("got err: '%s', want: '%s'", err.Error(), tc.wantErr)
				}
			}
		})
	}
}

func TestReadKeyPair_EmptyInput(t *testing.T) {
	pubCert, pk, err := ReadKeyPair([]byte{}, []byte{})
	if pubCert != nil {
		t.Errorf("pubCert = %v, want nil", pubCert)
	}
	if pk != nil {
		t.Errorf("pk = %v, want nil", pk)
	}
	if err == nil || !strings.Contains(err.Error(), "public certificate contains no PEM data") {
		t.Errorf("err = %v, want error containing %q", err, "public certificate contains no PEM data")
	}

	pubCert, pk, err = ReadKeyPair(nil, nil)
	if pubCert != nil {
		t.Errorf("pubCert = %v, want nil", pubCert)
	}
	if pk != nil {
		t.Errorf("pk = %v, want nil", pk)
	}
	if err == nil || !strings.Contains(err.Error(), "public certificate contains no PEM data") {
		t.Errorf("err = %v, want error containing %q", err, "public certificate contains no PEM data")
	}
}

func TestReadKeyPair_BadPublicCert(t *testing.T) {
	pubCert, pk, err := ReadKeyPair([]byte("bad"), []byte("bad"))
	if pubCert != nil {
		t.Errorf("pubCert = %v, want nil", pubCert)
	}
	if pk != nil {
		t.Errorf("pk = %v, want nil", pk)
	}
	if err == nil || !strings.Contains(err.Error(), "public certificate contains no PEM data") {
		t.Errorf("err = %v, want error containing %q", err, "public certificate contains no PEM data")
	}
}

func TestCreateCertificateAndPrivateKeyPEMErrors(t *testing.T) {
	ca, err := createCertificateAndPrivateKeyPEM(&Args{
		Validity:  time.Hour * 1,
		Hostnames: testHostnames,
		KeyType:   defaultKeyType(),
		CA:        true,
	})
	if err != nil {
		t.Fatal(err)
	}

	testCases := []struct {
		args    *Args
		wantErr string
	}{
		{
			args: &Args{
				KeyType: &KeyType{
					Algorithm: "lol",
					KeyLength: 10000,
				},
			},
			wantErr: "key algorithm, lol, is not valid",
		},
		{
			args: &Args{
				KeyType: &KeyType{
					Algorithm: rsaAlgorithm,
					KeyLength: 1,
				},
			},
			wantErr: "cannot generate private key, 'RSA-1' key type has a key length below 2048",
		},
		{
			args: &Args{
				KeyType: defaultKeyType(),
				ParentKeyPair: &KeyPair{
					PublicCertificate: []byte("lol"),
					PrivateKey:        []byte("lol"),
				},
			},
			wantErr: "public certificate contains no PEM data",
		},
		{
			args: &Args{
				KeyType:       defaultKeyType(),
				ParentKeyPair: ca,
				Issuer:        &Issuer{},
			},
			wantErr: "issuer and parent key pair are mutually exclusive",
		},
		{
			args: &Args{
				KeyType: defaultKeyType(),
				Issuer:  &Issuer{},
			},
			wantErr: "issuer must have both a certificate and a signer",
		},
	}
	for _, tc := range testCases {
		tc := tc
		t.Run(fmt.Sprintf("%v", tc), func(t *testing.T) {
			t.Parallel()

			kp, err := createCertificateAndPrivateKeyPEM(tc.args)
			if kp != nil {
				t.Errorf("KeyPair is not nil, got: %v", kp)
			}
			if err == nil {
				t.Errorf("error was nil, want: %s", tc.wantErr)
			}
			if err.Error() != tc.wantErr {
				t.Errorf("want err: '%s', got '%s'", tc.wantErr, err)
			}
		})
	}
}

func TestReadKeyPair_MalformedPublicCertificate(t *testing.T) {
	if testing.Short() {
		t.Skip("certificate generation takes a long time")
	}

	pair, err := createCertificateAndPrivateKeyPEM(&Args{
		KeyType: defaultKeyType(),
	})
	if err != nil {
		t.Fatalf("createCertificateAndPrivateKeyPEM() err = %v", err)
	}
	if pair.PrivateKey == nil {
		t.Fatal("pair.PrivateKey is nil")
	}
	if pair.PublicCertificate == nil {
		t.Fatal("pair.PublicCertificate is nil")
	}

	malformedPublicKey := []byte(strings.ReplaceAll(string(pair.PublicCertificate), "MII", "MIE"))

	pubCert, pk, err := ReadKeyPair(malformedPublicKey, pair.PrivateKey)
	if pubCert != nil {
		t.Errorf("pubCert = %v, want nil", pubCert)
	}
	if pk != nil {
		t.Errorf("pk = %v, want nil", pk)
	}
	if err == nil || !strings.Contains(err.Error(), "malformed") {
		t.Errorf("err = %v, want error containing %q", err, "malformed")
	}
}

func TestReadKeyPair_MalformedPrivateKey(t *testing.T) {
	if testing.Short() {
		t.Skip("certificate generation takes a long time")
	}

	pair, err := createCertificateAndPrivateKeyPEM(&Args{
		KeyType: defaultKeyType(),
	})
	if err != nil {
		t.Fatalf("createCertificateAndPrivateKeyPEM() err = %v", err)
	}
	if pair.PrivateKey == nil {
		t.Fatal("pair.PrivateKey is nil")
	}
	if pair.PublicCertificate == nil {
		t.Fatal("pair.PublicCertificate is nil")
	}
	malformedPriv := []byte(strings.ReplaceAll(string(pair.PrivateKey), rsaPrivateKeyPEMType, ecPrivateKeyPEMType))

	pubCert, pk, err := ReadKeyPair(pair.PublicCertificate, malformedPriv)
	if pubCert != nil {
		t.Errorf("pubCert = %v, want nil", pubCert)
	}
	if pk != nil {
		t.Errorf("pk = %v, want nil", pk)
	}
	if err == nil || !strings.Contains(err.Error(), "x509: failed to parse") {
		t.Errorf("err = %v, want error containing %q", err, "x509: failed to parse")
	}
	if err == nil || !strings.Contains(err.Error(), "private key") {
		t.Errorf("err = %v, want error containing %q", err, "private key")
	}

	malformedPriv = pair.PrivateKey
	for i := 500; i < 600; i++ {
		malformedPriv[i] = byte(0)
	}

	pubCert, pk, err = ReadKeyPair(pair.PublicCertificate, malformedPriv)
	if pubCert != nil {
		t.Errorf("pubCert = %v, want nil", pubCert)
	}
	if pk != nil {
		t.Errorf("pk = %v, want nil", pk)
	}
	if err == nil {
		t.Error("err = nil, want non-nil")
	}

	malformedPriv = []byte(strings.ReplaceAll(string(pair.PrivateKey), rsaPrivateKeyPEMType, "IDK"))

	pubCert, pk, err = ReadKeyPair(pair.PublicCertificate, malformedPriv)
	if pubCert != nil {
		t.Errorf("pubCert = %v, want nil", pubCert)
	}
	if pk != nil {
		t.Errorf("pk = %v, want nil", pk)
	}
	if err == nil || err.Error() == "" {
		t.Error("err is nil or empty, want non-empty error")
	}
}

func TestReadKeyPair_BadPrivateKey(t *testing.T) {
	if testing.Short() {
		t.Skip("certificate generation takes a long time")
	}

	pair, err := createCertificateAndPrivateKeyPEM(&Args{})
	if err != nil {
		t.Fatalf("createCertificateAndPrivateKeyPEM() err = %v", err)
	}
	if pair.PrivateKey == nil {
		t.Fatal("pair.PrivateKey is nil")
	}
	if pair.PublicCertificate == nil {
		t.Fatal("pair.PublicCertificate is nil")
	}

	pubCert, pk, err := ReadKeyPair(pair.PublicCertificate, []byte("bad"))
	if pubCert != nil {
		t.Errorf("pubCert = %v, want nil", pubCert)
	}
	if pk != nil {
		t.Errorf("pk = %v, want nil", pk)
	}
	if err == nil || !strings.Contains(err.Error(), "private key contains no PEM data") {
		t.Errorf("err = %v, want error containing %q", err, "private key contains no PEM data")
	}
}

func TestArgsToPkixName(t *testing.T) {
	testCases := []struct {
		input Args
		want  pkix.Name
	}{
		{
			Args{},
			pkix.Name{
				Country:            []string{""},
				Organization:       []string{""},
				OrganizationalUnit: []string{""},
				Locality:           []string{""},
				Province:           []string{""},
				CommonName:         "",
				SerialNumber:       "1",
			},
		},
		{
			Args{
				Country:            "country",
				Organization:       testOrgValue,
				OrganizationalUnit: "organizationUnit",
				Locality:           "locality",
				Province:           "province",
				CommonName:         testOrgValue,
			},
			pkix.Name{
				Country:            []string{"country"},
				Organization:       []string{testOrgValue},
				OrganizationalUnit: []string{"organizationUnit"},
				Locality:           []string{"locality"},
				Province:           []string{"province"},
				CommonName:         testOrgValue,
				SerialNumber:       "1",
			},
		},
	}
	for _, tc := range testCases {
		tc := tc
		t.Run(fmt.Sprintf("%v", tc.input), func(t *testing.T) {
			t.Parallel()
			actual := argsToPkixName(&tc.input, "1")
			if !reflect.DeepEqual(actual, tc.want) {
				t.Errorf("pkix.Name are different\ngot %v\nwant: %v", actual, tc.want)
			}
		})
	}
}

func TestCreateCACertificateWithECDSA(t *testing.T) {
	if testing.Short() {
		t.Skip("certificate generation takes a long time")
	}

	testCases := []struct {
		keyType KeyType
	}{
		{keyType: KeyType{Algorithm: ecdsaAlgorithm, KeyLength: 256}},
		{keyType: KeyType{Algorithm: ecdsaAlgorithm, KeyLength: 384}},
		{keyType: KeyType{Algorithm: ecdsaAlgorithm, KeyLength: 521}},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(fmt.Sprintf("%v", tc.keyType), func(t *testing.T) {
			t.Parallel()

			rootPair, err := createCertificateAndPrivateKeyPEM(&Args{
				Validity:  time.Hour * 1,
				Hostnames: testHostnames,
				KeyType:   &tc.keyType,
				CA:        true,
			})
			if err != nil {
				t.Fatalf("createCertificateAndPrivateKeyPEM(root) err = %v", err)
			}

			derivedPair, err := createCertificateAndPrivateKeyPEM(&Args{
				Validity:      time.Hour * 1,
				Hostnames:     testHostnames,
				KeyType:       &tc.keyType,
				CA:            false,
				ParentKeyPair: rootPair,
			})
			if err != nil {
				t.Fatalf("createCertificateAndPrivateKeyPEM(derived) err = %v", err)
			}

			rootPub, _, err := ReadKeyPair(rootPair.PublicCertificate, rootPair.PrivateKey)
			if err != nil {
				t.Fatalf("ReadKeyPair(root) err = %v", err)
			}
			if rootPub == nil {
				t.Fatal("rootPub is nil")
			}

			pub, pk, err := ReadKeyPair(derivedPair.PublicCertificate, derivedPair.PrivateKey)
			if err != nil {
				t.Fatalf("ReadKeyPair(derived) err = %v", err)
			}
			if pub == nil {
				t.Fatal("pub is nil")
			}
			if pk == nil {
				t.Fatal("pk is nil")
			}
			pkEcdsa, ok := pk.(*ecdsa.PrivateKey)
			if !ok {
				t.Fatalf("pk is %T, want *ecdsa.PrivateKey", pk)
			}
			pubEcdsa, ok := pub.PublicKey.(*ecdsa.PublicKey)
			if !ok {
				t.Fatalf("pub.PublicKey is %T, want *ecdsa.PublicKey", pub.PublicKey)
			}

			hash := sha256.Sum256([]byte(secretMessage))
			r, s, err := ecdsa.Sign(rand.Reader, pkEcdsa, hash[:])
			if err != nil {
				t.Fatalf("ecdsa.Sign() err = %v", err)
			}
			if verified := ecdsa.Verify(pubEcdsa, hash[:], r, s); !verified {
				t.Error("ecdsa.Verify() = false, want true")
			}

			pool := x509.NewCertPool()
			if ok = pool.AppendCertsFromPEM(rootPair.PublicCertificate); !ok {
				t.Error("AppendCertsFromPEM() = false, want true")
			}

			if err := pub.CheckSignatureFrom(rootPub); err != nil {
				t.Errorf("CheckSignatureFrom() err = %v", err)
			}
		})
	}
}

func TestGenerateKeyPair(t *testing.T) {
	if testing.Short() {
		t.Skip("certificate generation takes a long time")
	}

	rootPair, err := GenerateKeyPair(&Args{
		Hostnames: testHostnames,
	})
	if err != nil {
		t.Fatalf("GenerateKeyPair() err = %v", err)
	}

	publicCert, privateKey, err := ReadKeyPair(rootPair.PublicCertificate, rootPair.PrivateKey)
	if err != nil {
		t.Fatalf("ReadKeyPair() err = %v", err)
	}

	pkRSA, ok := privateKey.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("privateKey is %T, want *rsa.PrivateKey", privateKey)
	}
	pubRSA, ok := publicCert.PublicKey.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("publicCert.PublicKey is %T, want *rsa.PublicKey", publicCert.PublicKey)
	}

	hash := sha256.Sum256([]byte(secretMessage))

	sig, err := rsa.SignPKCS1v15(rand.Reader, pkRSA, crypto.SHA256, hash[:])
	if err != nil {
		t.Fatalf("SignPKCS1v15() err = %v", err)
	}
	if err = rsa.VerifyPKCS1v15(pubRSA, crypto.SHA256, hash[:], sig); err != nil {
		t.Errorf("VerifyPKCS1v15() err = %v", err)
	}
}

func TestFillDefaults(t *testing.T) {
	args := &Args{}
	fillDefaults(args)

	testCases := []struct {
		fieldName string
		got       string
		want      string
	}{
		{fieldName: "args.Country", got: args.Country, want: "US"},
		{fieldName: "args.Organization", got: args.Organization, want: defaultOrganization},
		{fieldName: "args.CommonName", got: args.CommonName, want: defaultOrganization},
		{fieldName: "args.OrganizationalUnit", got: args.OrganizationalUnit, want: "None"},
		{fieldName: "args.Locality", got: args.Locality, want: "Seattle"},
		{fieldName: "args.Province", got: args.Province, want: "WA"},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(fmt.Sprintf("%v", tc.fieldName), func(t *testing.T) {
			t.Parallel()
			if tc.got != tc.want {
				t.Errorf("%s = %s; want: %v", tc.fieldName, tc.got, tc.want)
			}
		})
	}
}

func TestCreateCertificateToBadPath(t *testing.T) {
	tmpDir := mustTemp(t)

	publicCertPath := filepath.Join(tmpDir, "public.crt")

	kp, err := GenerateAndWriteKeyPair(
		&Args{
			Validity:  time.Hour * 1,
			Hostnames: testHostnames,
			KeyType:   defaultKeyType(),
		},
		"does-not-exist/pub.crt",
		"does-not-exist/private.key",
	)

	if kp != nil {
		t.Errorf("kp = %v, want nil", kp)
	}
	if err == nil || !strings.Contains(err.Error(), "does-not-exist/pub.crt") {
		t.Errorf("err = %v, want error containing %q", err, "does-not-exist/pub.crt")
	}

	kp, err = GenerateAndWriteKeyPair(
		&Args{
			Validity:  time.Hour * 1,
			Hostnames: testHostnames,
			KeyType:   defaultKeyType(),
		},
		publicCertPath,
		"does-not-exist/private.key",
	)

	if kp != nil {
		t.Errorf("kp = %v, want nil", kp)
	}
	if err == nil || !strings.Contains(err.Error(), "does-not-exist/private.key") {
		t.Errorf("err = %v, want error containing %q", err, "does-not-exist/private.key")
	}
}

func TestCreateCertificate(t *testing.T) {
	if testing.Short() {
		t.Skip("certificate generation takes a long time")
	}

	tmpDir := mustTemp(t)

	publicCertPath := filepath.Join(tmpDir, "public.crt")
	privateKeyPath := filepath.Join(tmpDir, "private.key")

	kp, err := GenerateAndWriteKeyPair(&Args{
		Validity:  time.Hour * 1,
		Hostnames: testHostnames,
		KeyType:   defaultKeyType(),
	},
		publicCertPath, privateKeyPath)
	if err != nil {
		t.Fatal(err)
	}

	if kp == nil {
		t.Fatal("kp is nil")
	}

	if _, err := os.Stat(publicCertPath); err != nil {
		t.Errorf("public cert file does not exist: %v", err)
	}
	if _, err := os.Stat(privateKeyPath); err != nil {
		t.Errorf("private key file does not exist: %v", err)
	}

	publicCertFileData, err := os.ReadFile(filepath.Clean(publicCertPath))
	if err != nil {
		t.Fatalf("ReadFile(publicCert) err = %v", err)
	}

	privateKeyFileData, err := os.ReadFile(filepath.Clean(privateKeyPath))
	if err != nil {
		t.Fatalf("ReadFile(privateKey) err = %v", err)
	}

	pub, pk, err := ReadKeyPair(publicCertFileData, privateKeyFileData)
	if err != nil {
		t.Fatalf("ReadKeyPair() err = %v", err)
	}
	pkRSA, ok := pk.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("pk is %T, want *rsa.PrivateKey", pk)
	}

	pubKey, ok := pub.PublicKey.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("pub.PublicKey is %T, want *rsa.PublicKey", pub.PublicKey)
	}

	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pubKey, []byte(secretMessage), []byte{})
	if err != nil {
		t.Fatalf("EncryptOAEP() err = %v", err)
	}
	if string(ciphertext) == secretMessage {
		t.Error("ciphertext equals plaintext")
	}

	cleartext, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, pkRSA, ciphertext, []byte{})
	if err != nil {
		t.Fatalf("DecryptOAEP() err = %v", err)
	}
	if string(cleartext) != secretMessage {
		t.Errorf("cleartext = %q, want %q", string(cleartext), secretMessage)
	}
}

func TestBadValues(t *testing.T) {
	testCases := []struct {
		errorString string
		pub         string
		priv        string
		args        *Args
	}{
		{
			"root public certificate data was set but root private key data was not", testPubCertFile, testPrivKeyFile,
			&Args{ParentKeyPair: &KeyPair{PublicCertificate: []byte("A")}, Validity: time.Second, Hostnames: []string{testLoopbackIP}, KeyType: defaultKeyType()},
		},
		{
			"root private key data was set but root public certificate data was not", testPubCertFile, testPrivKeyFile,
			&Args{ParentKeyPair: &KeyPair{PrivateKey: []byte("A")}, Validity: time.Second, Hostnames: []string{testLoopbackIP}, KeyType: defaultKeyType()},
		},
		{"public certificate file path must not be empty", "", testPrivKeyFile, &Args{Validity: time.Second, Hostnames: []string{testLoopbackIP}, KeyType: defaultKeyType()}},
		{"private key file path must not be empty", testPubCertFile, "", &Args{Validity: time.Second, Hostnames: []string{testLoopbackIP}, KeyType: defaultKeyType()}},
		{"cannot generate private key, key type '{ECDSA 2047}' is not valid", testPubCertFile, testPrivKeyFile, &Args{Validity: time.Second, Hostnames: []string{testLoopbackIP}, KeyType: &KeyType{
			Algorithm: ecdsaAlgorithm,
			KeyLength: 2047,
		}}},
	}
	for _, tc := range testCases {
		tc := tc
		t.Run(tc.errorString, func(t *testing.T) {
			t.Parallel()
			kp, err := GenerateAndWriteKeyPair(tc.args, tc.pub, tc.priv)
			if kp != nil {
				t.Errorf("KeyPair should be nil, got: %+v", kp)
			}
			if err == nil {
				t.Errorf("Expected an error with text, '%s'", tc.errorString)
			} else if err.Error() != tc.errorString {
				t.Errorf("Expected an error with text, '%s', got '%s'", tc.errorString, err)
			}
		})
	}
}

func TestParseName(t *testing.T) {
	testCases := []struct {
		subject  string
		expected pkix.Name
	}{
		{"/C=GB/ST=London/L=London/O=Global Security/OU=IT Department/CN=example.com", pkix.Name{
			Country:            []string{"GB"},
			Province:           []string{"London"},
			Locality:           []string{"London"},
			Organization:       []string{"Global Security"},
			OrganizationalUnit: []string{"IT Department"},
			CommonName:         testExampleCom,
		}},
		{"////////////CN=example.com", pkix.Name{
			CommonName: testExampleCom,
		}},
		{"STREET=123 Main Street/POSTALCODE=12345", pkix.Name{
			StreetAddress: []string{"123 Main Street"},
			PostalCode:    []string{"12345"},
		}},
		{`CN=foo\/bar`, pkix.Name{
			CommonName: "foo/bar",
		}},
	}
	for _, tc := range testCases {
		tc := tc
		t.Run(tc.subject, func(t *testing.T) {
			t.Parallel()
			actual, err := ParseName(tc.subject)
			if err != nil {
				t.Errorf("Unexpected error for input '%s', %v", tc.subject, err)
			}
			if !reflect.DeepEqual(actual, tc.expected) {
				t.Errorf("pkix.Name are different\ngot %v\nexpected: %v", actual, tc.expected)
			}
		})
	}
}

func TestBadParseName(t *testing.T) {
	testCases := []struct {
		subject  string
		expected string
	}{
		{"/LOL=CODE", "'LOL' is not a valid RFC-2253 AttributeType"},
		{"/ST=CODE=OK", "AttributeType 'ST' has too many parts, [ST CODE OK]"},
	}
	for _, tc := range testCases {
		tc := tc
		t.Run(tc.subject, func(t *testing.T) {
			t.Parallel()
			_, err := ParseName(tc.subject)
			if err == nil {
				t.Errorf("Expected error '%s' for input %v", tc.expected, tc.subject)
			} else if err.Error() != tc.expected {
				t.Errorf("Expected error '%s' for input %v, got '%s'", tc.expected, tc.subject, err.Error())
			}
		})
	}
}

func TestPemBlockForKey_errors(t *testing.T) {
	block, err := pemBlockForKey("ok")
	if block != nil {
		t.Errorf("block = %v, want nil", block)
	}
	if err == nil || !strings.Contains(err.Error(), "not a valid private key") {
		t.Errorf("err = %v, want error containing %q", err, "not a valid private key")
	}

	block, err = pemBlockForKey(&ecdsa.PrivateKey{})
	if block != nil {
		t.Errorf("block = %v, want nil", block)
	}
	if err == nil || !strings.Contains(err.Error(), "unknown elliptic curve") {
		t.Errorf("err = %v, want error containing %q", err, "unknown elliptic curve")
	}
}

func TestGenerateCodeSigningKeyPair_Windows10(t *testing.T) {
	if testing.Short() {
		t.Skip("certificate generation takes a long time")
	}

	kp, err := GenerateKeyPair(&Args{
		CodeSigning: true,
		Target:      windows10Target,
	})
	if err != nil {
		t.Fatalf("GenerateKeyPair() err = %v", err)
	}
	if len(kp.PFX) == 0 {
		t.Error("kp.PFX is empty")
	}
	if len(kp.PublicCertificate) == 0 {
		t.Error("kp.PublicCertificate is empty")
	}
	if len(kp.PrivateKey) == 0 {
		t.Error("kp.PrivateKey is empty")
	}

	pub, _, err := ReadKeyPair(kp.PublicCertificate, kp.PrivateKey)
	if err != nil {
		t.Fatalf("ReadKeyPair() err = %v", err)
	}
	if pub.KeyUsage != x509.KeyUsageDigitalSignature {
		t.Errorf("KeyUsage = %v, want %v", pub.KeyUsage, x509.KeyUsageDigitalSignature)
	}
	if !reflect.DeepEqual(pub.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}) {
		t.Errorf("ExtKeyUsage = %v, want [CodeSigning]", pub.ExtKeyUsage)
	}
	if len(pub.DNSNames) != 0 {
		t.Errorf("DNSNames = %v, want empty", pub.DNSNames)
	}
	if len(pub.IPAddresses) != 0 {
		t.Errorf("IPAddresses = %v, want empty", pub.IPAddresses)
	}
}

func TestGenerateCodeSigningKeyPair_Windows7(t *testing.T) {
	if testing.Short() {
		t.Skip("certificate generation takes a long time")
	}

	kp, err := GenerateKeyPair(&Args{
		CodeSigning: true,
		Target:      windows7Target,
	})
	if err != nil {
		t.Fatalf("GenerateKeyPair() err = %v", err)
	}
	if kp == nil {
		t.Fatal("kp is nil")
	}
	if len(kp.PFX) == 0 {
		t.Error("kp.PFX is empty")
	}

	pub, _, err := ReadKeyPair(kp.PublicCertificate, kp.PrivateKey)
	if err != nil {
		t.Fatalf("ReadKeyPair() err = %v", err)
	}
	if pub.KeyUsage != x509.KeyUsageDigitalSignature {
		t.Errorf("KeyUsage = %v, want %v", pub.KeyUsage, x509.KeyUsageDigitalSignature)
	}
	if !reflect.DeepEqual(pub.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}) {
		t.Errorf("ExtKeyUsage = %v, want [CodeSigning]", pub.ExtKeyUsage)
	}
	if len(pub.DNSNames) != 0 {
		t.Errorf("DNSNames = %v, want empty", pub.DNSNames)
	}
	if len(pub.IPAddresses) != 0 {
		t.Errorf("IPAddresses = %v, want empty", pub.IPAddresses)
	}
}

func TestGenerateCodeSigningKeyPair_Linux(t *testing.T) {
	if testing.Short() {
		t.Skip("certificate generation takes a long time")
	}

	kp, err := GenerateKeyPair(&Args{
		CodeSigning: true,
		Target:      linuxTarget,
	})
	if err != nil {
		t.Fatalf("GenerateKeyPair() err = %v", err)
	}
	if kp == nil {
		t.Fatal("kp is nil")
	}
	if len(kp.PFX) != 0 {
		t.Errorf("kp.PFX = %d bytes, want empty for linux target", len(kp.PFX))
	}
	if len(kp.PublicCertificate) == 0 {
		t.Error("kp.PublicCertificate is empty")
	}
	if len(kp.PrivateKey) == 0 {
		t.Error("kp.PrivateKey is empty")
	}

	pub, _, err := ReadKeyPair(kp.PublicCertificate, kp.PrivateKey)
	if err != nil {
		t.Fatalf("ReadKeyPair() err = %v", err)
	}
	if pub.KeyUsage != x509.KeyUsageDigitalSignature {
		t.Errorf("KeyUsage = %v, want %v", pub.KeyUsage, x509.KeyUsageDigitalSignature)
	}
	if !reflect.DeepEqual(pub.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}) {
		t.Errorf("ExtKeyUsage = %v, want [CodeSigning]", pub.ExtKeyUsage)
	}
}

func TestGenerateCodeSigningKeyPair_DefaultTarget(t *testing.T) {
	if testing.Short() {
		t.Skip("certificate generation takes a long time")
	}

	kp, err := GenerateKeyPair(&Args{CodeSigning: true})
	if err != nil {
		t.Fatalf("GenerateKeyPair() err = %v", err)
	}
	if kp == nil {
		t.Fatal("kp is nil")
	}
	if len(kp.PFX) == 0 {
		t.Error("kp.PFX is empty; windows10 is the default target and should produce PFX output")
	}
}

func TestGenerateCodeSigningKeyPair_WithPassword(t *testing.T) {
	if testing.Short() {
		t.Skip("certificate generation takes a long time")
	}

	kp, err := GenerateKeyPair(&Args{
		CodeSigning: true,
		Target:      windows10Target,
		PFXPassword: "hunter2",
	})
	if err != nil {
		t.Fatalf("GenerateKeyPair() err = %v", err)
	}
	if len(kp.PFX) == 0 {
		t.Fatal("kp.PFX is empty")
	}

	if _, _, err = pkcs12.Decode(kp.PFX, "hunter2"); err != nil {
		t.Errorf("pkcs12.Decode(correct password) err = %v", err)
	}

	if _, _, err = pkcs12.Decode(kp.PFX, "wrongpassword"); err == nil {
		t.Error("pkcs12.Decode(wrong password) err = nil, want error")
	}
}

func TestGenerateCodeSigningKeyPair_InvalidTarget(t *testing.T) {
	kp, err := GenerateKeyPair(&Args{
		CodeSigning: true,
		Target:      "windowsXP",
	})
	if kp != nil {
		t.Error("kp should be nil on invalid target")
	}
	if err == nil {
		t.Error("expected error for unknown target")
	}
}

func TestWritePFX(t *testing.T) {
	if testing.Short() {
		t.Skip("certificate generation takes a long time")
	}

	tmpDir := mustTemp(t)
	pfxPath := filepath.Join(tmpDir, "codesign.pfx")

	kp, err := GenerateKeyPair(&Args{
		CodeSigning: true,
		Target:      windows10Target,
	})
	if err != nil {
		t.Fatalf("GenerateKeyPair() err = %v", err)
	}

	if err = WritePFX(kp, pfxPath); err != nil {
		t.Fatalf("WritePFX() err = %v", err)
	}
	if _, err := os.Stat(pfxPath); err != nil {
		t.Errorf("pfx file does not exist: %v", err)
	}

	info, err := os.Stat(pfxPath)
	if err != nil {
		t.Fatalf("Stat() err = %v", err)
	}
	if runtime.GOOS != "windows" {
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("file permissions = %o, want 0600", perm)
		}
	}
}

// Regenerating over existing files must not keep their permissions or write
// through symbolic links, or the new private key could end up readable by
// others or somewhere else entirely.
func TestWriteKeyPair_ReplacesExistingFiles(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file modes and symlinks behave differently on Windows")
	}

	dir := mustTemp(t)
	certPath := filepath.Join(dir, "app.crt")
	keyPath := filepath.Join(dir, "app.key")
	if err := os.WriteFile(keyPath, []byte("old key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(keyPath, 0o644); err != nil { //nolint:gosec // The test needs a world-readable key to replace.
		t.Fatal(err)
	}
	victim := filepath.Join(dir, "victim")
	if err := os.Symlink(victim, certPath); err != nil {
		t.Fatal(err)
	}

	kp := &KeyPair{PublicCertificate: []byte("cert"), PrivateKey: []byte("key")}
	if err := WriteKeyPair(kp, certPath, keyPath); err != nil {
		t.Fatalf("WriteKeyPair() err = %v", err)
	}

	for path, want := range map[string]os.FileMode{certPath: 0o644, keyPath: 0o600} {
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		if !info.Mode().IsRegular() || info.Mode().Perm() != want {
			t.Errorf("%s has mode %v, want a regular file with mode %o", path, info.Mode(), want)
		}
	}
	if _, err := os.Lstat(victim); !os.IsNotExist(err) {
		t.Errorf("the certificate was written through the symlink to %s (stat err = %v)", victim, err)
	}
}

func TestWritePFX_NoPFXData(t *testing.T) {
	err := WritePFX(&KeyPair{}, "out.pfx")
	if err == nil || !strings.Contains(err.Error(), "does not contain PKCS#12 data") {
		t.Errorf("err = %v, want error containing %q", err, "does not contain PKCS#12 data")
	}
}

func mustTemp(tb testing.TB) string {
	tmpDir, err := os.MkdirTemp("", "certtest")
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() {
		if err := os.RemoveAll(tmpDir); err != nil {
			tb.Errorf("cannot delete temp directory '%s', %s", tmpDir, err)
		}
	})
	return tmpDir
}

func TestSubjectAltNames(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		name      string
		hostnames []string
		wantDNS   []string
		wantIPs   []string
	}{
		{name: "empty", hostnames: nil},
		{name: "blank entries", hostnames: []string{"", " "}},
		{name: "sorted and deduplicated", hostnames: []string{"b.com", testExampleCom, "B.com", testExampleCom}, wantDNS: []string{"b.com", testExampleCom}},
		{name: "port removed", hostnames: []string{testMixHostPort, "mix.com"}, wantDNS: []string{"mix.com"}},
		{name: "IPv4 with port", hostnames: []string{testLoopbackIPPort}, wantIPs: []string{"192.168.1.1"}},
		{name: "IPv6", hostnames: []string{"[::1]:8080", "::1", "2001:db8::1"}, wantIPs: []string{"2001:db8::1", "::1"}},
		{name: "trailing dot", hostnames: []string{"example.com."}, wantDNS: []string{testExampleCom}},
		{name: "wildcard", hostnames: []string{"*.example.com"}, wantDNS: []string{"*.example.com"}},
		{name: "mixed", hostnames: []string{testDupHostPort, "10.0.0.1", "localhost"}, wantDNS: []string{"dup.com", "localhost"}, wantIPs: []string{"10.0.0.1"}},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dns, ips, err := subjectAltNames(tc.hostnames)
			if err != nil {
				t.Fatalf("subjectAltNames() err = %v", err)
			}
			gotIPs := make([]string, 0, len(ips))
			for _, ip := range ips {
				gotIPs = append(gotIPs, ip.String())
			}
			if diff := cmp.Diff(tc.wantDNS, dns, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("DNS names mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(tc.wantIPs, gotIPs, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("IP addresses mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestValidateEmailAddress(t *testing.T) {
	t.Parallel()
	for _, email := range []string{"alice@example.com", "a.b+git@sub.example.co.uk"} {
		if err := ValidateEmailAddress(email); err != nil {
			t.Errorf("ValidateEmailAddress(%q) err = %v", email, err)
		}
	}
	for _, email := range []string{"", "alice", "Alice <alice@example.com>", " alice@example.com", "alice@", "alice@*.example.com", "alice@exa mple.com"} {
		if err := ValidateEmailAddress(email); err == nil {
			t.Errorf("ValidateEmailAddress(%q) err = nil, want an error", email)
		}
	}
}

func TestValidateHostname(t *testing.T) {
	t.Parallel()
	for _, hostname := range []string{
		testExampleCom, "a.example.com:443", "localhost", "my-host", "_dmarc.example.com", "xn--bcher-kva.example",
		"*.example.com", "*.a.example.com", "10.0.0.1", "::1", "[::1]:443", strings.Repeat("a", 63) + ".com",
	} {
		if err := ValidateHostname(hostname); err != nil {
			t.Errorf("ValidateHostname(%q) err = %v, want nil", hostname, err)
		}
	}

	for hostname, want := range map[string]string{
		"*":                              "a wildcard needs at least two labels after it",
		"*.com":                          "a wildcard needs at least two labels after it",
		"a*.example.com":                 "a wildcard must be the whole leftmost label",
		"www.*.example.com":              "a wildcard must be the whole leftmost label",
		"a..com":                         "it has an empty label",
		".":                              "it is empty",
		"-a.com":                         `the label "-a" starts or ends with a hyphen`,
		"a b.com":                        `has the character ' '`,
		"bücher.example":                 "punycode",
		strings.Repeat("a", 64) + ".com": "is longer than 63 characters",
		strings.Repeat("a.", 127) + "a":  "is longer than 253 characters",
	} {
		err := ValidateHostname(hostname)
		if err == nil || !strings.Contains(err.Error(), want) || !strings.Contains(err.Error(), "is not a valid DNS name or IP address") {
			t.Errorf("ValidateHostname(%q) err = %v, want it to contain %q", hostname, err, want)
		}
	}
}

// Certificate names cannot hold ports, so a port on a hostname is removed.
func TestGenerateKeyPair_PortsNotInSANs(t *testing.T) {
	t.Parallel()
	hostnames := []string{"api.example.com", "web.example.com:8443"}
	kp, err := GenerateKeyPair(&Args{
		KeyType:   &KeyType{Algorithm: ecdsaAlgorithm, KeyLength: 256},
		Hostnames: hostnames,
	})
	if err != nil {
		t.Fatalf("GenerateKeyPair() err = %v", err)
	}
	cert, _, err := ReadKeyPair(kp.PublicCertificate, kp.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff([]string{"api.example.com", "localhost", "web.example.com"}, cert.DNSNames); diff != "" {
		t.Errorf("DNSNames mismatch (-want +got):\n%s", diff)
	}
	if len(cert.IPAddresses) != 1 || cert.IPAddresses[0].String() != "127.0.0.1" {
		t.Errorf("IPAddresses = %v, want [127.0.0.1]", cert.IPAddresses)
	}
	if err := cert.VerifyHostname("api.example.com"); err != nil {
		t.Errorf("VerifyHostname() err = %v", err)
	}
	if diff := cmp.Diff([]string{"api.example.com", "web.example.com:8443"}, hostnames); diff != "" {
		t.Errorf("GenerateKeyPair() changed the caller's Hostnames (-want +got):\n%s", diff)
	}
}

func TestGenerateKeyPair_InvalidHostname(t *testing.T) {
	t.Parallel()
	_, err := GenerateKeyPair(&Args{KeyType: &KeyType{Algorithm: ecdsaAlgorithm, KeyLength: 256}, Hostnames: []string{"*.com"}})
	if err == nil || !strings.Contains(err.Error(), `hostname "*.com" is not a valid DNS name`) {
		t.Errorf("GenerateKeyPair() err = %v, want an invalid hostname error", err)
	}
}

func TestGetHostnames(t *testing.T) {
	t.Parallel()
	args := &Args{Hostnames: []string{"b.com:443", "a.com", "", "b.com"}}
	if diff := cmp.Diff([]string{"a.com", "b.com"}, args.GetHostnames()); diff != "" {
		t.Errorf("GetHostnames() mismatch (-want +got):\n%s", diff)
	}
}

func BenchmarkSubjectAltNames(b *testing.B) {
	for b.Loop() {
		if _, _, err := subjectAltNames([]string{testExampleCom, "test.com", "localhost", "127.0.0.1"}); err != nil {
			b.Fatal(err)
		}
	}
}

// ReadKeyPair accepts PKCS#8 keys, the format openssl genpkey writes, and says
// what to do with an encrypted one.
func TestReadKeyPair_PKCS8(t *testing.T) {
	t.Parallel()
	for _, keyType := range []*KeyType{{Algorithm: rsaAlgorithm, KeyLength: 2048}, {Algorithm: ecdsaAlgorithm, KeyLength: 256}} {
		t.Run(keyType.Algorithm, func(t *testing.T) {
			t.Parallel()
			kp, err := GenerateKeyPair(&Args{CA: true, KeyType: keyType})
			if err != nil {
				t.Fatal(err)
			}
			_, key, err := ReadKeyPair(kp.PublicCertificate, kp.PrivateKey)
			if err != nil {
				t.Fatal(err)
			}
			der, err := x509.MarshalPKCS8PrivateKey(key)
			if err != nil {
				t.Fatal(err)
			}
			pkcs8 := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

			if _, _, err := ReadKeyPair(kp.PublicCertificate, pkcs8); err != nil {
				t.Errorf("ReadKeyPair(PKCS#8) err = %v", err)
			}
			// The PKCS#8 key works as a parent.
			if _, err := GenerateKeyPair(&Args{KeyType: keyType, ParentKeyPair: &KeyPair{PublicCertificate: kp.PublicCertificate, PrivateKey: pkcs8}}); err != nil {
				t.Errorf("GenerateKeyPair() with a PKCS#8 parent key err = %v", err)
			}
		})
	}

	kp, err := GenerateKeyPair(&Args{KeyType: &KeyType{Algorithm: ecdsaAlgorithm, KeyLength: 256}})
	if err != nil {
		t.Fatal(err)
	}
	encrypted := pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: []byte("opaque")})
	if _, _, err := ReadKeyPair(kp.PublicCertificate, encrypted); err == nil || !strings.Contains(err.Error(), "the private key is encrypted") {
		t.Errorf("ReadKeyPair(encrypted) err = %v, want an encrypted key error", err)
	}
	broken := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("not DER")})
	if _, _, err := ReadKeyPair(kp.PublicCertificate, broken); err == nil || !strings.Contains(err.Error(), "cannot parse PKCS8 private key") {
		t.Errorf("ReadKeyPair(broken PKCS#8) err = %v, want a parse error", err)
	}
}

// The signature hash matches the strength of the signing key.
func TestGenerateKeyPair_SignatureAlgorithm(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		keyType     KeyType
		codeSigning bool
		want        x509.SignatureAlgorithm
	}{
		{KeyType{rsaAlgorithm, 2048}, false, x509.SHA256WithRSA},
		{KeyType{rsaAlgorithm, 2048}, true, x509.SHA256WithRSA},
		{KeyType{ecdsaAlgorithm, 256}, false, x509.ECDSAWithSHA256},
		{KeyType{ecdsaAlgorithm, 384}, false, x509.ECDSAWithSHA384},
		{KeyType{ecdsaAlgorithm, 521}, false, x509.ECDSAWithSHA512},
		{KeyType{ecdsaAlgorithm, 384}, true, x509.ECDSAWithSHA256},
	} {
		keyType := tc.keyType
		kp, err := GenerateKeyPair(&Args{KeyType: &keyType, CodeSigning: tc.codeSigning, Target: linuxTarget})
		if err != nil {
			t.Fatalf("GenerateKeyPair(%v) err = %v", tc.keyType, err)
		}
		cert, _, err := ReadKeyPair(kp.PublicCertificate, kp.PrivateKey)
		if err != nil {
			t.Fatal(err)
		}
		if cert.SignatureAlgorithm != tc.want {
			t.Errorf("%v (code signing %t): SignatureAlgorithm = %v, want %v", tc.keyType, tc.codeSigning, cert.SignatureAlgorithm, tc.want)
		}
	}
}

func TestGenerateKeyPair_RejectsWeakOrIncompleteECDSA(t *testing.T) {
	t.Parallel()
	for length, want := range map[int]string{224: "ECDSA-224 is not supported", 0: "an ECDSA key type needs a curve size"} {
		_, err := GenerateKeyPair(&Args{KeyType: &KeyType{Algorithm: ecdsaAlgorithm, KeyLength: length}})
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("GenerateKeyPair(ECDSA-%d) err = %v, want it to contain %q", length, err, want)
		}
	}
}
