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
	"net"
	"strings"
	"testing"
)

func mustParseCIDRs(t *testing.T, cidrs ...string) []*net.IPNet {
	t.Helper()

	ranges, err := ParseIPRanges(cidrs)
	if err != nil {
		t.Fatal(err)
	}
	return ranges
}

func intPtr(i int) *int { return &i }

// generateCert generates a certificate from args and returns it parsed, with
// its key pair.
func generateCert(t *testing.T, args *Args) (*x509.Certificate, *KeyPair) {
	t.Helper()

	if args.KeyType == nil {
		args.KeyType = testECDSA256
	}
	kp, err := GenerateKeyPair(args)
	if err != nil {
		t.Fatalf("GenerateKeyPair() err = %v", err)
	}
	return parseCertificatePEM(t, kp.PublicCertificate), kp
}

// A CA is not a server: it gets no names and no key encipherment.
func TestGenerateKeyPair_CAHasNoServerExtensions(t *testing.T) {
	t.Parallel()
	for _, keyType := range []*KeyType{testECDSA256, {Algorithm: rsaAlgorithm, KeyLength: 2048}} {
		ca, _ := generateCert(t, &Args{CA: true, KeyType: keyType, Hostnames: []string{"ca.example.com"}})
		if len(ca.DNSNames) != 0 || len(ca.IPAddresses) != 0 {
			t.Errorf("%s CA has SANs %v %v, want none", keyType.Algorithm, ca.DNSNames, ca.IPAddresses)
		}
		if want := x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature; ca.KeyUsage != want {
			t.Errorf("%s CA key usage = %v, want %v", keyType.Algorithm, ca.KeyUsage, want)
		}
		if ca.MaxPathLen != -1 || ca.MaxPathLenZero {
			t.Errorf("%s CA path length = %d (zero %t), want no limit", keyType.Algorithm, ca.MaxPathLen, ca.MaxPathLenZero)
		}
	}
}

func TestGenerateKeyPair_MaxPathLen(t *testing.T) {
	t.Parallel()
	root, rootKP := generateCert(t, &Args{CA: true, MaxPathLen: intPtr(0)})
	if root.MaxPathLen != 0 || !root.MaxPathLenZero {
		t.Fatalf("root path length = %d (zero %t), want 0", root.MaxPathLen, root.MaxPathLenZero)
	}
	if _, err := GenerateKeyPair(&Args{CA: true, KeyType: testECDSA256, ParentKeyPair: rootKP}); err == nil || !strings.Contains(err.Error(), "has a path length of 0") {
		t.Errorf("GenerateKeyPair() of a CA under a path length 0 root err = %v, want a path length error", err)
	}
	generateCert(t, &Args{ParentKeyPair: rootKP})

	two, _ := generateCert(t, &Args{CA: true, MaxPathLen: intPtr(2)})
	if two.MaxPathLen != 2 {
		t.Errorf("path length = %d, want 2", two.MaxPathLen)
	}
	if _, err := GenerateKeyPair(&Args{CA: true, KeyType: testECDSA256, MaxPathLen: intPtr(-1)}); err == nil {
		t.Error("GenerateKeyPair() with path length -1 err = nil, want an error")
	}
}

// Name constraints limit what the CA's certificates may name. certtool must
// refuse names a client would reject, and drop its own localhost names
// instead of failing.
func TestGenerateKeyPair_NameConstraints(t *testing.T) {
	t.Parallel()
	ca, caKP := generateCert(t, &Args{
		CA:                  true,
		PermittedDNSDomains: []string{"example.com", ".internal"},
		PermittedIPRanges:   mustParseCIDRs(t, "10.0.0.0/8"),
	})
	if !ca.PermittedDNSDomainsCritical {
		t.Error("name constraints are not critical")
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)

	leaf, _ := generateCert(t, &Args{ParentKeyPair: caKP, Hostnames: []string{"api.example.com", "*.svc.internal", "10.1.2.3"}})
	if len(leaf.DNSNames) != 2 || len(leaf.IPAddresses) != 1 {
		t.Errorf("leaf names = %v %v, want api.example.com, *.svc.internal, and 10.1.2.3 without localhost", leaf.DNSNames, leaf.IPAddresses)
	}
	for _, name := range []string{"api.example.com", "10.1.2.3"} {
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: name}); err != nil {
			t.Errorf("Verify(%s) err = %v", name, err)
		}
	}

	for hostname, want := range map[string]string{
		"evil.com":       `only permits the DNS domains example.com, .internal, so clients would reject the name "evil.com"`,
		"internal":       `reject the name "internal"`,
		"notexample.com": `reject the name "notexample.com"`,
		"192.168.1.1":    "only permits the IP ranges 10.0.0.0/8, so clients would reject the address 192.168.1.1",
	} {
		_, err := GenerateKeyPair(&Args{KeyType: testECDSA256, ParentKeyPair: caKP, Hostnames: []string{hostname}})
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("GenerateKeyPair(%s) err = %v, want it to contain %q", hostname, err, want)
		}
	}
}

// A CA that constrains only DNS names leaves IP addresses alone.
func TestGenerateKeyPair_DNSOnlyConstraintsKeepIPs(t *testing.T) {
	t.Parallel()
	_, caKP := generateCert(t, &Args{CA: true, PermittedDNSDomains: []string{"example.com"}})
	leaf, _ := generateCert(t, &Args{ParentKeyPair: caKP, Hostnames: []string{"a.example.com", "192.168.1.1"}})
	if len(leaf.IPAddresses) != 2 || len(leaf.DNSNames) != 1 {
		t.Errorf("leaf names = %v %v, want a.example.com, 127.0.0.1, and 192.168.1.1", leaf.DNSNames, leaf.IPAddresses)
	}
}

func TestGenerateKeyPair_InvalidPermittedDomain(t *testing.T) {
	t.Parallel()
	_, err := GenerateKeyPair(&Args{CA: true, KeyType: testECDSA256, PermittedDNSDomains: []string{"bad domain"}})
	if err == nil || !strings.Contains(err.Error(), `permitted DNS domain "bad domain" is not valid`) {
		t.Errorf("GenerateKeyPair() err = %v, want an invalid domain error", err)
	}
}

// The root CA for a hardware key keeps the path length and name constraints.
func TestCreateSelfSignedCertificate_Constraints(t *testing.T) {
	t.Parallel()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := CreateSelfSignedCertificate(&Args{CA: true, MaxPathLen: intPtr(1), PermittedDNSDomains: []string{"example.com"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	if cert.MaxPathLen != 1 || len(cert.PermittedDNSDomains) != 1 || len(cert.ExtKeyUsage) != 0 {
		t.Errorf("root = path length %d, domains %v, EKU %v; want 1, [example.com], none", cert.MaxPathLen, cert.PermittedDNSDomains, cert.ExtKeyUsage)
	}
}

func TestDNSNamePermitted(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		domains []string
		want    bool
	}{
		{"example.com", []string{"example.com"}, true},
		{"a.b.example.com", []string{"example.com"}, true},
		{"EXAMPLE.com", []string{"example.com"}, true},
		{"example.com", []string{".example.com"}, false},
		{"a.example.com", []string{".example.com"}, true},
		{"*.example.com", []string{".example.com"}, true},
		{"badexample.com", []string{"example.com"}, false},
		{"localhost", []string{"example.com"}, false},
	} {
		if got := dnsNamePermitted(tc.name, tc.domains); got != tc.want {
			t.Errorf("dnsNamePermitted(%q, %v) = %t, want %t", tc.name, tc.domains, got, tc.want)
		}
	}
}

// A CA below a constrained CA inherits the constraints, so certificates two
// levels down are still kept within them and verify.
func TestGenerateKeyPair_NameConstraintsInherited(t *testing.T) {
	t.Parallel()
	root, rootKP := generateCert(t, &Args{CA: true, PermittedDNSDomains: []string{"example.com"}, PermittedIPRanges: mustParseCIDRs(t, "10.0.0.0/8")})
	issuing, issuingKP := generateCert(t, &Args{CA: true, MaxPathLen: intPtr(0), ParentKeyPair: rootKP})
	if len(issuing.PermittedDNSDomains) != 1 || len(issuing.PermittedIPRanges) != 1 || !issuing.PermittedDNSDomainsCritical {
		t.Fatalf("issuing CA constraints = %v %v (critical %t), want the root's", issuing.PermittedDNSDomains, issuing.PermittedIPRanges, issuing.PermittedDNSDomainsCritical)
	}

	leaf, _ := generateCert(t, &Args{ParentKeyPair: issuingKP, Hostnames: []string{"api.example.com"}})
	if len(leaf.DNSNames) != 1 || len(leaf.IPAddresses) != 0 {
		t.Errorf("leaf names = %v %v, want only api.example.com", leaf.DNSNames, leaf.IPAddresses)
	}
	roots, intermediates := x509.NewCertPool(), x509.NewCertPool()
	roots.AddCert(root)
	intermediates.AddCert(issuing)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, DNSName: "api.example.com"}); err != nil {
		t.Errorf("Verify() err = %v", err)
	}

	narrower, _ := generateCert(t, &Args{CA: true, ParentKeyPair: rootKP, PermittedDNSDomains: []string{"api.example.com"}, PermittedIPRanges: mustParseCIDRs(t, "10.1.0.0/16")})
	if len(narrower.PermittedDNSDomains) != 1 || narrower.PermittedDNSDomains[0] != "api.example.com" {
		t.Errorf("narrower CA domains = %v, want [api.example.com]", narrower.PermittedDNSDomains)
	}

	for name, args := range map[string]*Args{
		"domain outside": {CA: true, KeyType: testECDSA256, ParentKeyPair: rootKP, PermittedDNSDomains: []string{"example.org"}},
		"range outside":  {CA: true, KeyType: testECDSA256, ParentKeyPair: rootKP, PermittedIPRanges: mustParseCIDRs(t, "192.168.0.0/16")},
		"range wider":    {CA: true, KeyType: testECDSA256, ParentKeyPair: rootKP, PermittedIPRanges: mustParseCIDRs(t, "10.0.0.0/7")},
	} {
		if _, err := GenerateKeyPair(args); err == nil || !strings.Contains(err.Error(), "is outside the") {
			t.Errorf("%s: GenerateKeyPair() err = %v, want an outside the parent's constraints error", name, err)
		}
	}
}
