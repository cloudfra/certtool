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
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	testSpecRootCA    = "Root CA"
	testSpecLeafCom   = "leaf.example.com"
	testSpecRSA2048   = "RSA-2048"
	testSpecECDSA256  = "ECDSA-256"
	testSpecValidity  = "8760h"
	testSpecWindows10 = "windows10"
)

func TestUnmarshalSpec_Valid(t *testing.T) {
	t.Parallel()
	input := []byte(`
- commonName: "Root CA"
  certificateAuthority: true
  children:
    - commonName: "leaf.example.com"
      hostnames:
        - leaf.example.com
`)
	specs, err := UnmarshalSpec(input)
	if err != nil {
		t.Fatalf("UnmarshalSpec() err = %v", err)
	}
	if len(specs) != 1 {
		t.Fatalf("got %d specs, want 1", len(specs))
	}
	if specs[0].CommonName != testSpecRootCA {
		t.Errorf("root CN = %q, want %q", specs[0].CommonName, testSpecRootCA)
	}
	if !specs[0].CertificateAuthority {
		t.Error("root CertificateAuthority = false, want true")
	}
	if len(specs[0].Children) != 1 {
		t.Fatalf("root has %d children, want 1", len(specs[0].Children))
	}
	if specs[0].Children[0].CommonName != testSpecLeafCom {
		t.Errorf("child CN = %q, want %q", specs[0].Children[0].CommonName, testSpecLeafCom)
	}
}

func TestUnmarshalSpec_MultipleRoots(t *testing.T) {
	t.Parallel()
	input := []byte(`
- commonName: "TLS Root CA"
  certificateAuthority: true
  children:
    - commonName: "web.example.com"
- commonName: "Code Signing Cert"
  codeSigning: true
  target: "windows10"
`)
	specs, err := UnmarshalSpec(input)
	if err != nil {
		t.Fatalf("UnmarshalSpec() err = %v", err)
	}
	if len(specs) != 2 {
		t.Fatalf("got %d specs, want 2", len(specs))
	}
	if !specs[1].CodeSigning {
		t.Error("second spec CodeSigning = false, want true")
	}
	if specs[1].Target != testSpecWindows10 {
		t.Errorf("second spec Target = %q, want %q", specs[1].Target, testSpecWindows10)
	}
}

func TestUnmarshalSpec_NonCARoot(t *testing.T) {
	t.Parallel()
	input := []byte(`
- commonName: "standalone.example.com"
  hostnames:
    - standalone.example.com
`)
	specs, err := UnmarshalSpec(input)
	if err != nil {
		t.Fatalf("UnmarshalSpec() err = %v", err)
	}
	if specs[0].CertificateAuthority {
		t.Error("CertificateAuthority = true, want false")
	}
}

func TestUnmarshalSpec_AllFields(t *testing.T) {
	t.Parallel()
	input := []byte(`
- commonName: "My Cert"
  certificateAuthority: true
  codeSigning: false
  target: "windows10"
  pfxPassword: "secret"
  keyType: "RSA-4096"
  validity: "87600h"
  organization: "Acme"
  organizationalUnit: "Engineering"
  country: "US"
  locality: "Portland"
  province: "OR"
  hostnames:
    - app.example.com
    - localhost
  ports: [443, 8443]
  filename: "my-cert"
  children:
    - commonName: "Child"
`)
	specs, err := UnmarshalSpec(input)
	if err != nil {
		t.Fatalf("UnmarshalSpec() err = %v", err)
	}
	s := specs[0]
	if s.Target != testSpecWindows10 {
		t.Errorf("Target = %q", s.Target)
	}
	if s.PFXPassword != "secret" {
		t.Errorf("PFXPassword = %q", s.PFXPassword)
	}
	if s.KeyType != "RSA-4096" {
		t.Errorf("KeyType = %q", s.KeyType)
	}
	if s.Validity != "87600h" {
		t.Errorf("Validity = %q", s.Validity)
	}
	if s.Organization != "Acme" {
		t.Errorf("Organization = %q", s.Organization)
	}
	if s.OrganizationalUnit != "Engineering" {
		t.Errorf("OrganizationalUnit = %q", s.OrganizationalUnit)
	}
	if s.Country != "US" {
		t.Errorf("Country = %q", s.Country)
	}
	if s.Locality != "Portland" {
		t.Errorf("Locality = %q", s.Locality)
	}
	if s.Province != "OR" {
		t.Errorf("Province = %q", s.Province)
	}
	if len(s.Hostnames) != 2 {
		t.Errorf("Hostnames = %v", s.Hostnames)
	}
	if len(s.Ports) != 2 || s.Ports[0] != 443 || s.Ports[1] != 8443 {
		t.Errorf("Ports = %v", s.Ports)
	}
	if s.Filename != "my-cert" {
		t.Errorf("Filename = %q", s.Filename)
	}
	if len(s.Children) != 1 {
		t.Errorf("Children = %v", s.Children)
	}
}

func TestUnmarshalSpec_Errors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		yaml    string
		wantErr string
	}{
		{
			name:    "empty spec",
			yaml:    "[]\n",
			wantErr: "must have at least one certificate",
		},
		{
			name:    "children without CA",
			yaml:    "- commonName: Root\n  children:\n    - commonName: Leaf\n",
			wantErr: "has children but certificateAuthority is not true",
		},
		{
			name:    "empty CN",
			yaml:    "- certificateAuthority: true\n",
			wantErr: "must have a commonName",
		},
		{
			name:    "nested empty CN",
			yaml:    "- commonName: Root\n  certificateAuthority: true\n  children:\n    - certificateAuthority: false\n",
			wantErr: "must have a commonName",
		},
		{
			name:    "invalid YAML",
			yaml:    "not: valid: yaml: [",
			wantErr: "cannot parse spec YAML",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := UnmarshalSpec([]byte(tc.yaml))
			if err == nil {
				t.Fatal("UnmarshalSpec() = nil error, want error")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("err = %q, want containing %q", err.Error(), tc.wantErr)
			}
		})
	}
}

func TestReadSpec_NotFound(t *testing.T) {
	t.Parallel()
	_, err := ReadSpec("does-not-exist.yaml")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
	if !strings.Contains(err.Error(), "cannot read spec file") {
		t.Errorf("err = %q, want containing %q", err.Error(), "cannot read spec file")
	}
}

func TestMarshalSpec_RoundTrip(t *testing.T) {
	t.Parallel()
	specs := []CertificateSpec{{
		CommonName:           testSpecRootCA,
		CertificateAuthority: true,
		KeyType:              "RSA-4096",
		Children: []CertificateSpec{{
			CommonName: testSpecLeafCom,
			Hostnames:  []string{testSpecLeafCom},
		}},
	}}

	data, err := MarshalSpec(specs)
	if err != nil {
		t.Fatalf("MarshalSpec() err = %v", err)
	}

	roundTrip, err := UnmarshalSpec(data)
	if err != nil {
		t.Fatalf("UnmarshalSpec(marshaled) err = %v", err)
	}
	if roundTrip[0].CommonName != testSpecRootCA {
		t.Errorf("round-trip CN = %q, want %q", roundTrip[0].CommonName, testSpecRootCA)
	}
	if !roundTrip[0].CertificateAuthority {
		t.Error("round-trip CertificateAuthority = false")
	}
	if len(roundTrip[0].Children) != 1 {
		t.Fatalf("round-trip children = %d, want 1", len(roundTrip[0].Children))
	}
	if roundTrip[0].Children[0].CommonName != testSpecLeafCom {
		t.Errorf("round-trip child CN = %q, want %q", roundTrip[0].Children[0].CommonName, testSpecLeafCom)
	}
}

func TestGenerateFromSpec_SimpleChain(t *testing.T) {
	if testing.Short() {
		t.Skip("certificate generation takes a long time")
	}

	outputDir := t.TempDir()
	specs := []CertificateSpec{
		{
			CommonName:           "Test Root CA",
			CertificateAuthority: true,
			KeyType:              testSpecRSA2048,
			Validity:             testSpecValidity,
			Children: []CertificateSpec{
				{
					CommonName: testSpecLeafCom,
					KeyType:    testSpecRSA2048,
					Hostnames:  []string{testSpecLeafCom},
					Validity:   "720h",
				},
			},
		},
	}

	results, err := GenerateFromSpec(specs, outputDir)
	if err != nil {
		t.Fatalf("GenerateFromSpec() err = %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("got %d results, want 2", len(results))
	}

	for _, r := range results {
		if _, err := os.Stat(r.CertPath); err != nil {
			t.Errorf("cert file %q missing: %v", r.CertPath, err)
		}
		if _, err := os.Stat(r.KeyPath); err != nil {
			t.Errorf("key file %q missing: %v", r.KeyPath, err)
		}
	}

	rootCert := parseGenCert(t, results[0])
	if !rootCert.IsCA {
		t.Error("root IsCA = false, want true")
	}

	leafCert := parseGenCert(t, results[1])
	if leafCert.IsCA {
		t.Error("leaf IsCA = true, want false")
	}
	if err := leafCert.CheckSignatureFrom(rootCert); err != nil {
		t.Errorf("leaf not signed by root: %v", err)
	}
}

func TestGenerateFromSpec_MultiLeaf(t *testing.T) {
	if testing.Short() {
		t.Skip("certificate generation takes a long time")
	}

	outputDir := t.TempDir()
	specs := []CertificateSpec{
		{
			CommonName:           testSpecRootCA,
			CertificateAuthority: true,
			KeyType:              testSpecECDSA256,
			Validity:             testSpecValidity,
			Children: []CertificateSpec{
				{CommonName: "frontend.local", KeyType: testSpecECDSA256, Filename: "frontend"},
				{CommonName: "backend.local", KeyType: testSpecECDSA256, Filename: "backend"},
			},
		},
	}

	results, err := GenerateFromSpec(specs, outputDir)
	if err != nil {
		t.Fatalf("GenerateFromSpec() err = %v", err)
	}
	if len(results) != 3 {
		t.Fatalf("got %d results, want 3", len(results))
	}

	if results[1].CertPath != filepath.Join(outputDir, "frontend.cert") {
		t.Errorf("frontend path = %q", results[1].CertPath)
	}
	if results[2].CertPath != filepath.Join(outputDir, "backend.cert") {
		t.Errorf("backend path = %q", results[2].CertPath)
	}
}

func TestGenerateFromSpec_FilenameCollision(t *testing.T) {
	if testing.Short() {
		t.Skip("certificate generation takes a long time")
	}

	outputDir := t.TempDir()
	specs := []CertificateSpec{
		{
			CommonName:           testSpecRootCA,
			CertificateAuthority: true,
			KeyType:              testSpecRSA2048,
			Validity:             testSpecValidity,
			Children: []CertificateSpec{
				{CommonName: "a", Filename: "same", KeyType: testSpecRSA2048},
				{CommonName: "b", Filename: "same", KeyType: testSpecRSA2048},
			},
		},
	}

	_, err := GenerateFromSpec(specs, outputDir)
	if err == nil {
		t.Fatal("expected filename collision error")
	}
	if !strings.Contains(err.Error(), "filename collision") {
		t.Errorf("err = %q, want containing %q", err.Error(), "filename collision")
	}
}

func TestGenerateFromSpec_CodeSigning(t *testing.T) {
	if testing.Short() {
		t.Skip("certificate generation takes a long time")
	}

	outputDir := t.TempDir()
	specs := []CertificateSpec{
		{
			CommonName:  "Test Code Signing",
			CodeSigning: true,
			Target:      testSpecWindows10,
			Validity:    testSpecValidity,
			Filename:    "codesign",
		},
	}

	results, err := GenerateFromSpec(specs, outputDir)
	if err != nil {
		t.Fatalf("GenerateFromSpec() err = %v", err)
	}
	if results[0].PFXPath == "" {
		t.Error("PFXPath is empty, want PFX for code signing")
	}
	if _, err := os.Stat(results[0].PFXPath); err != nil {
		t.Errorf("PFX file missing: %v", err)
	}
}

func parseGenCert(t *testing.T, result GenerationOutput) *x509.Certificate {
	t.Helper()
	cert, _, err := ReadKeyPair(result.KeyPair.PublicCertificate, result.KeyPair.PrivateKey)
	if err != nil {
		t.Fatalf("ReadKeyPair() for %q err = %v", result.CommonName, err)
	}
	return cert
}

func TestGenerateFromSpec_Examples(t *testing.T) {
	if testing.Short() {
		t.Skip("certificate generation takes a long time")
	}

	tests := []struct {
		file      string
		wantCerts int
	}{
		{file: "simple-chain.yaml", wantCerts: 2},
		{file: "multi-service.yaml", wantCerts: 4},
		{file: "intermediate-ca.yaml", wantCerts: 4},
		{file: "code-signing.yaml", wantCerts: 1},
		{file: "mixed-roots.yaml", wantCerts: 4},
	}

	for _, tc := range tests {
		t.Run(tc.file, func(t *testing.T) {
			specs, err := ReadSpec(filepath.Join("testdata", tc.file))
			if err != nil {
				t.Fatalf("ReadSpec(%q) err = %v", tc.file, err)
			}

			outputDir := t.TempDir()
			results, err := GenerateFromSpec(specs, outputDir)
			if err != nil {
				t.Fatalf("GenerateFromSpec() err = %v", err)
			}
			if len(results) != tc.wantCerts {
				t.Fatalf("got %d results, want %d", len(results), tc.wantCerts)
			}

			for _, r := range results {
				if _, err := os.Stat(r.CertPath); err != nil {
					t.Errorf("cert file %q missing: %v", r.CertPath, err)
				}
				if _, err := os.Stat(r.KeyPath); err != nil {
					t.Errorf("key file %q missing: %v", r.KeyPath, err)
				}
				if r.PFXPath != "" {
					if _, err := os.Stat(r.PFXPath); err != nil {
						t.Errorf("pfx file %q missing: %v", r.PFXPath, err)
					}
				}
			}
		})
	}
}

func TestGenerateFromSpec_IntermediateChainVerify(t *testing.T) {
	if testing.Short() {
		t.Skip("certificate generation takes a long time")
	}

	specs, err := ReadSpec(filepath.Join("testdata", "intermediate-ca.yaml"))
	if err != nil {
		t.Fatalf("ReadSpec() err = %v", err)
	}

	results, err := GenerateFromSpec(specs, t.TempDir())
	if err != nil {
		t.Fatalf("GenerateFromSpec() err = %v", err)
	}

	root := parseGenCert(t, results[0])
	intermediate := parseGenCert(t, results[1])
	leaf := parseGenCert(t, results[2])

	if !root.IsCA {
		t.Error("root IsCA = false")
	}
	if !intermediate.IsCA {
		t.Error("intermediate IsCA = false")
	}
	if leaf.IsCA {
		t.Error("leaf IsCA = true")
	}

	if err := intermediate.CheckSignatureFrom(root); err != nil {
		t.Errorf("intermediate not signed by root: %v", err)
	}
	if err := leaf.CheckSignatureFrom(intermediate); err != nil {
		t.Errorf("leaf not signed by intermediate: %v", err)
	}
}

func TestGenerateFromSpec_Stress(t *testing.T) {
	if testing.Short() {
		t.Skip("certificate generation takes a long time")
	}

	const leafCount = 20
	children := make([]CertificateSpec, leafCount)
	for i := range children {
		children[i] = CertificateSpec{
			CommonName: fmt.Sprintf("leaf-%03d.stress.local", i),
			KeyType:    testSpecECDSA256,
			Hostnames:  []string{fmt.Sprintf("leaf-%03d.stress.local", i)},
		}
	}

	specs := []CertificateSpec{
		{
			CommonName:           "Stress Root CA",
			CertificateAuthority: true,
			KeyType:              testSpecECDSA256,
			Validity:             testSpecValidity,
			Children:             children,
		},
	}

	outputDir := t.TempDir()
	results, err := GenerateFromSpec(specs, outputDir)
	if err != nil {
		t.Fatalf("GenerateFromSpec() err = %v", err)
	}

	wantTotal := 1 + leafCount
	if len(results) != wantTotal {
		t.Fatalf("got %d results, want %d", len(results), wantTotal)
	}

	root := parseGenCert(t, results[0])
	if !root.IsCA {
		t.Error("root IsCA = false")
	}

	for i := 1; i < len(results); i++ {
		leaf := parseGenCert(t, results[i])
		if leaf.IsCA {
			t.Errorf("leaf[%d] IsCA = true", i)
		}
		if err := leaf.CheckSignatureFrom(root); err != nil {
			t.Errorf("leaf[%d] not signed by root: %v", i, err)
		}
	}

	entries, err := os.ReadDir(outputDir)
	if err != nil {
		t.Fatalf("ReadDir() err = %v", err)
	}
	wantFiles := wantTotal * 2
	if len(entries) != wantFiles {
		t.Errorf("output dir has %d files, want %d", len(entries), wantFiles)
	}
}
