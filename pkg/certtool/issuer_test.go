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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"
)

// newTestIssuer returns an Issuer backed by an in-memory ECDSA key, standing in
// for a key held on a hardware token.
func newTestIssuer(t *testing.T) *Issuer {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := CreateSelfSignedCertificate(&Args{CA: true, CommonName: "Token Root CA", Validity: time.Hour}, key)
	if err != nil {
		t.Fatalf("CreateSelfSignedCertificate() err = %v", err)
	}
	return &Issuer{Certificate: cert, Signer: key}
}

func parsePEMCertificate(t *testing.T, data []byte) *x509.Certificate {
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

func verifyChain(t *testing.T, root *x509.Certificate, leaf *x509.Certificate, intermediates ...*x509.Certificate) {
	t.Helper()

	roots := x509.NewCertPool()
	roots.AddCert(root)
	pool := x509.NewCertPool()
	for _, c := range intermediates {
		pool.AddCert(c)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: pool}); err != nil {
		t.Errorf("certificate %q does not chain to %q: %v", leaf.Subject.CommonName, root.Subject.CommonName, err)
	}
}

func TestCreateSelfSignedCertificate(t *testing.T) {
	issuer := newTestIssuer(t)
	cert := issuer.Certificate

	if !cert.IsCA {
		t.Error("IsCA = false, want true")
	}
	if want := x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature; cert.KeyUsage != want {
		t.Errorf("KeyUsage = %v, want %v", cert.KeyUsage, want)
	}
	if len(cert.ExtKeyUsage) != 0 || len(cert.DNSNames) != 0 || len(cert.IPAddresses) != 0 {
		t.Errorf("root CA has ExtKeyUsage %v, DNSNames %v, and IPAddresses %v, want none", cert.ExtKeyUsage, cert.DNSNames, cert.IPAddresses)
	}
	if cert.SignatureAlgorithm != x509.ECDSAWithSHA512 {
		t.Errorf("SignatureAlgorithm = %v, want %v", cert.SignatureAlgorithm, x509.ECDSAWithSHA512)
	}
	if err := cert.CheckSignatureFrom(cert); err != nil {
		t.Errorf("certificate is not self-signed: %v", err)
	}

	roundTrip := parsePEMCertificate(t, EncodeCertificatePEM(cert))
	if !roundTrip.Equal(cert) {
		t.Error("EncodeCertificatePEM() did not round trip the certificate")
	}
}

func TestGenerateKeyPair_Issuer(t *testing.T) {
	if testing.Short() {
		t.Skip("certificate generation takes a long time")
	}

	issuer := newTestIssuer(t)

	// The RSA leaf is signed by the ECDSA issuer, so the signature algorithm
	// must follow the issuer's key, not the leaf's.
	kp, err := GenerateKeyPair(&Args{
		CommonName: testExampleCom,
		Hostnames:  []string{testExampleCom},
		KeyType:    defaultKeyType(),
		Issuer:     issuer,
	})
	if err != nil {
		t.Fatalf("GenerateKeyPair() err = %v", err)
	}

	leaf := parsePEMCertificate(t, kp.PublicCertificate)
	if leaf.SignatureAlgorithm != x509.ECDSAWithSHA512 {
		t.Errorf("SignatureAlgorithm = %v, want %v", leaf.SignatureAlgorithm, x509.ECDSAWithSHA512)
	}
	if leaf.KeyUsage&x509.KeyUsageKeyEncipherment == 0 {
		t.Error("RSA leaf KeyUsage does not include KeyEncipherment")
	}
	verifyChain(t, issuer.Certificate, leaf)
}

func TestGenerateKeyPair_MixedAlgorithmParent(t *testing.T) {
	if testing.Short() {
		t.Skip("certificate generation takes a long time")
	}

	root, err := GenerateKeyPair(&Args{CA: true, CommonName: "RSA Root CA", KeyType: defaultKeyType()})
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := GenerateKeyPair(&Args{
		CommonName:    testExampleCom,
		KeyType:       &KeyType{Algorithm: ecdsaAlgorithm, KeyLength: 256},
		ParentKeyPair: root,
	})
	if err != nil {
		t.Fatalf("GenerateKeyPair() err = %v", err)
	}

	leafCert := parsePEMCertificate(t, leaf.PublicCertificate)
	if leafCert.SignatureAlgorithm != x509.SHA512WithRSA {
		t.Errorf("SignatureAlgorithm = %v, want %v", leafCert.SignatureAlgorithm, x509.SHA512WithRSA)
	}
	verifyChain(t, parsePEMCertificate(t, root.PublicCertificate), leafCert)
}

func TestGenerateFromSpecWithIssuer(t *testing.T) {
	if testing.Short() {
		t.Skip("certificate generation takes a long time")
	}

	issuer := newTestIssuer(t)
	specs := []CertificateSpec{
		{
			CommonName:           "Intermediate CA",
			CertificateAuthority: true,
			KeyType:              testSpecECDSA256,
			Children: []CertificateSpec{
				{CommonName: testSpecLeafCom, KeyType: testSpecECDSA256, Hostnames: []string{testSpecLeafCom}},
			},
		},
		{CommonName: "standalone.example.com", KeyType: testSpecRSA2048},
	}

	results, err := GenerateFromSpecWithIssuer(specs, t.TempDir(), issuer)
	if err != nil {
		t.Fatalf("GenerateFromSpecWithIssuer() err = %v", err)
	}
	if len(results) != 3 {
		t.Fatalf("got %d results, want 3", len(results))
	}

	intermediate := parseGenCert(t, results[0])
	leaf := parseGenCert(t, results[1])
	standalone := parseGenCert(t, results[2])

	verifyChain(t, issuer.Certificate, intermediate)
	verifyChain(t, issuer.Certificate, leaf, intermediate)
	verifyChain(t, issuer.Certificate, standalone)
	if err := leaf.CheckSignatureFrom(intermediate); err != nil {
		t.Errorf("leaf not signed by intermediate: %v", err)
	}
}

func TestGenerateKeyPair_IssuerCodeSigning(t *testing.T) {
	issuer := newTestIssuer(t)

	kp, err := GenerateKeyPair(&Args{
		CommonName:  "Acme Code Signing",
		CodeSigning: true,
		KeyType:     &KeyType{Algorithm: ecdsaAlgorithm, KeyLength: 256},
		Issuer:      issuer,
	})
	if err != nil {
		t.Fatalf("GenerateKeyPair() err = %v", err)
	}

	leaf := parsePEMCertificate(t, kp.PublicCertificate)
	roots := x509.NewCertPool()
	roots.AddCert(issuer.Certificate)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}}); err != nil {
		t.Errorf("code signing certificate does not verify for code signing: %v", err)
	}
}
