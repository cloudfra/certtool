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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

var testECDSA256 = &KeyType{Algorithm: ecdsaAlgorithm, KeyLength: 256}

// parentKeyPair returns a self-signed ECDSA P-256 CA, changed by edit, as the
// PEM key pair that --parent-public-certificate and --parent-private-key read.
func parentKeyPair(t *testing.T, edit func(*x509.Certificate)) *KeyPair {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Parent CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            -1,
	}
	if edit != nil {
		edit(template)
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return &KeyPair{
		PublicCertificate: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		PrivateKey:        pem.EncodeToMemory(&pem.Block{Type: ecPrivateKeyPEMType, Bytes: keyDER}),
	}
}

// A parent that cannot issue the certificate must be rejected instead of
// producing a certificate that clients will not accept.
func TestGenerateKeyPair_RejectsUnusableParent(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		edit    func(*x509.Certificate)
		args    Args
		wantErr string
	}{
		{
			name:    "not a CA",
			edit:    func(c *x509.Certificate) { c.IsCA, c.KeyUsage = false, x509.KeyUsageDigitalSignature },
			wantErr: `parent certificate "Test Parent CA" is not a CA certificate`,
		},
		{
			name:    "no basic constraints",
			edit:    func(c *x509.Certificate) { c.BasicConstraintsValid, c.IsCA, c.MaxPathLen = false, false, 0 },
			wantErr: "is not a CA certificate",
		},
		{
			name:    "no cert sign key usage",
			edit:    func(c *x509.Certificate) { c.KeyUsage = x509.KeyUsageDigitalSignature },
			wantErr: "does not allow certificate signing",
		},
		{
			name: "expired",
			edit: func(c *x509.Certificate) {
				c.NotBefore, c.NotAfter = time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour)
			},
			wantErr: "expired at",
		},
		{
			name: "not yet valid",
			edit: func(c *x509.Certificate) {
				c.NotBefore, c.NotAfter = time.Now().Add(24*time.Hour), time.Now().Add(48*time.Hour)
			},
			wantErr: "is not valid until",
		},
		{
			name:    "path length 0 signing a CA",
			edit:    func(c *x509.Certificate) { c.MaxPathLen, c.MaxPathLenZero = 0, true },
			args:    Args{CA: true},
			wantErr: "has a path length of 0",
		},
		{
			name: "TLS-only CA signing code signing",
			edit: func(c *x509.Certificate) {
				c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
			},
			args:    Args{CodeSigning: true, Target: linuxTarget},
			wantErr: "is limited to TLS server and TLS client, so clients would reject a code signing certificate it signs; sign code signing certificates with",
		},
		{
			name:    "server-only CA signing a TLS certificate",
			edit:    func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth} },
			wantErr: "is limited to TLS server, so clients would reject a TLS client certificate it signs",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			args := tc.args
			args.KeyType = testECDSA256
			args.ParentKeyPair = parentKeyPair(t, tc.edit)
			_, err := GenerateKeyPair(&args)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("GenerateKeyPair() err = %v, want it to contain %q", err, tc.wantErr)
			}
		})
	}
}

func TestGenerateKeyPair_AcceptsUsableParent(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		edit func(*x509.Certificate)
		args Args
	}{
		{name: "TLS leaf under an unrestricted CA"},
		{name: "code signing under an unrestricted CA", args: Args{CodeSigning: true, Target: linuxTarget}},
		{name: "intermediate CA under an unrestricted CA", args: Args{CA: true}},
		{
			name: "intermediate CA under a path length 1 CA",
			edit: func(c *x509.Certificate) { c.MaxPathLen = 1 },
			args: Args{CA: true},
		},
		{
			name: "leaf under a path length 0 CA",
			edit: func(c *x509.Certificate) { c.MaxPathLen, c.MaxPathLenZero = 0, true },
		},
		{
			name: "TLS leaf under a TLS CA",
			edit: func(c *x509.Certificate) {
				c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
			},
		},
		{
			name: "code signing under an any-usage CA",
			edit: func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageAny} },
			args: Args{CodeSigning: true, Target: linuxTarget},
		},
		{
			name: "key usage not set",
			edit: func(c *x509.Certificate) { c.KeyUsage = 0 },
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			args := tc.args
			args.KeyType = testECDSA256
			args.ParentKeyPair = parentKeyPair(t, tc.edit)
			if _, err := GenerateKeyPair(&args); err != nil {
				t.Errorf("GenerateKeyPair() err = %v, want nil", err)
			}
		})
	}
}

// A certificate must not outlive its issuer, so its validity is cut short.
func TestGenerateKeyPair_ValidityCappedAtParent(t *testing.T) {
	t.Parallel()
	parent := parentKeyPair(t, nil)
	parentCert, _, err := ReadKeyPair(parent.PublicCertificate, parent.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}

	for name, validity := range map[string]time.Duration{"longer": 10 * oneYear, "shorter": time.Hour} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			kp, err := GenerateKeyPair(&Args{KeyType: testECDSA256, Validity: validity, ParentKeyPair: parent})
			if err != nil {
				t.Fatalf("GenerateKeyPair() err = %v", err)
			}
			cert := parseCertificatePEM(t, kp.PublicCertificate)
			want := cert.NotBefore.Add(validity)
			if want.After(parentCert.NotAfter) {
				want = parentCert.NotAfter
			}
			if got := cert.NotAfter; got.Sub(want).Abs() > time.Second {
				t.Errorf("NotAfter = %s, want %s", got, want)
			}

			roots := x509.NewCertPool()
			roots.AddCert(parentCert)
			if _, err := cert.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
				t.Errorf("Verify() err = %v", err)
			}
		})
	}
}

func parseCertificatePEM(t *testing.T, data []byte) *x509.Certificate {
	t.Helper()

	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatal("no PEM data")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}
