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
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/crypto/ssh"
	"software.sslmate.com/src/go-pkcs12"
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
			name:    "unknown pfx format",
			yaml:    "- commonName: Server\n  pfx: aes\n",
			wantErr: `unknown .pfx format "aes"`,
		},
		{
			name:    "emailAddresses on a CA",
			yaml:    "- commonName: CA\n  certificateAuthority: true\n  emailAddresses: [ca@example.com]\n",
			wantErr: "emailAddresses, which only apply to a leaf",
		},
		{
			name:    "emailAddresses on code signing",
			yaml:    "- commonName: Signer\n  codeSigning: true\n  emailAddresses: [a@example.com]\n",
			wantErr: "emailAddresses, which only apply to a leaf",
		},
		{
			name:    "bad email address",
			yaml:    "- commonName: Alice\n  emailAddresses: [\"Alice <alice@example.com>\"]\n",
			wantErr: "bare address",
		},
		{
			name:    "sshPublicKey on a CA",
			yaml:    "- commonName: CA\n  certificateAuthority: true\n  sshPublicKey: true\n",
			wantErr: "sshPublicKey on a CA",
		},
		{
			name:    "pfx on code signing",
			yaml:    "- commonName: Signer\n  codeSigning: true\n  pfx: modern\n",
			wantErr: "whose target decides its .pfx",
		},
		{
			name:    "nested empty CN",
			yaml:    "- commonName: Root\n  certificateAuthority: true\n  children:\n    - certificateAuthority: false\n",
			wantErr: "must have a commonName",
		},
		{
			name:    "code signing under a TLS CA",
			yaml:    "- commonName: Root\n  certificateAuthority: true\n  children:\n    - commonName: Sign\n      codeSigning: true\n",
			wantErr: `spec "Sign" has codeSigning true but its parent "Root" has codeSigning false`,
		},
		{
			name:    "TLS under a code signing CA",
			yaml:    "- commonName: Root\n  certificateAuthority: true\n  codeSigning: true\n  children:\n    - commonName: web\n",
			wantErr: `spec "web" has codeSigning false but its parent "Root" has codeSigning true`,
		},
		{
			name:    "filename with parent directory",
			yaml:    "- commonName: x\n  filename: ../../escaped\n",
			wantErr: `has filename "../../escaped", which must be a file name`,
		},
		{
			name:    "filename with directory",
			yaml:    "- commonName: x\n  filename: sub/x\n",
			wantErr: "must be a file name",
		},
		{
			name:    "filename with backslash",
			yaml:    "- commonName: x\n  filename: ..\\x\n",
			wantErr: "must be a file name",
		},
		{
			name:    "absolute filename",
			yaml:    "- commonName: x\n  filename: /etc/x\n",
			wantErr: "must be a file name",
		},
		{
			name:    "dot-dot filename",
			yaml:    "- commonName: x\n  filename: ..\n",
			wantErr: "must be a file name",
		},
		{
			name:    "nested filename with parent directory",
			yaml:    "- commonName: Root\n  certificateAuthority: true\n  children:\n    - commonName: Leaf\n      filename: ../leaf\n",
			wantErr: `spec "Leaf" has filename "../leaf"`,
		},
		{
			name:    "pfxPassword and pfxPasswordEnv",
			yaml:    "- commonName: Sign\n  codeSigning: true\n  pfxPassword: x\n  pfxPasswordEnv: PW\n",
			wantErr: `spec "Sign" sets both pfxPassword and pfxPasswordEnv`,
		},
		{
			name:    "constraints on a leaf",
			yaml:    "- commonName: Leaf\n  maxPathLen: 0\n",
			wantErr: `spec "Leaf" sets maxPathLen, permittedDNSDomains, or permittedIPRanges, which only apply to a CA`,
		},
		{
			name:    "negative maxPathLen",
			yaml:    "- commonName: CA\n  certificateAuthority: true\n  maxPathLen: -2\n",
			wantErr: `spec "CA" has maxPathLen -2`,
		},
		{
			name:    "bad IP range",
			yaml:    "- commonName: CA\n  certificateAuthority: true\n  permittedIPRanges: [10.0.0.0]\n",
			wantErr: `permitted IP range "10.0.0.0" is not in CIDR notation`,
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

func TestChainToSpec_Depth2(t *testing.T) {
	t.Parallel()
	specs, err := ChainToSpec([]int{1, 1}, "leaf.local", "Acme", "")
	if err != nil {
		t.Fatalf("ChainToSpec() err = %v", err)
	}
	if len(specs) != 1 {
		t.Fatalf("got %d roots, want 1", len(specs))
	}
	root := specs[0]
	if root.CommonName != "Acme Root CA" {
		t.Errorf("root CN = %q, want %q", root.CommonName, "Acme Root CA")
	}
	if !root.CertificateAuthority {
		t.Error("root CA = false, want true")
	}
	if len(root.Children) != 1 {
		t.Fatalf("root has %d children, want 1", len(root.Children))
	}
	if root.Children[0].CommonName != "leaf.local" {
		t.Errorf("leaf CN = %q, want %q", root.Children[0].CommonName, "leaf.local")
	}
	if root.Children[0].CertificateAuthority {
		t.Error("leaf CA = true, want false")
	}
}

func TestChainToSpec_Depth4(t *testing.T) {
	t.Parallel()
	specs, err := ChainToSpec([]int{1, 1, 1, 1}, "", "TestOrg", "")
	if err != nil {
		t.Fatalf("ChainToSpec() err = %v", err)
	}
	root := specs[0]
	if root.CommonName != "TestOrg Root CA" {
		t.Errorf("root CN = %q", root.CommonName)
	}
	inter1 := root.Children[0]
	if inter1.CommonName != "TestOrg Intermediate 1 CA" {
		t.Errorf("intermediate 1 CN = %q", inter1.CommonName)
	}
	if !inter1.CertificateAuthority {
		t.Error("intermediate 1 CA = false")
	}
	inter2 := inter1.Children[0]
	if inter2.CommonName != "TestOrg Intermediate 2 CA" {
		t.Errorf("intermediate 2 CN = %q", inter2.CommonName)
	}
	leaf := inter2.Children[0]
	if leaf.CommonName != "TestOrg" {
		t.Errorf("leaf CN = %q, want %q", leaf.CommonName, "TestOrg")
	}
	if leaf.CertificateAuthority {
		t.Error("leaf CA = true")
	}
}

func TestChainToSpec_Empty(t *testing.T) {
	t.Parallel()
	if _, err := ChainToSpec([]int{}, "", "", ""); err == nil {
		t.Fatal("ChainToSpec([]) = nil error, want error")
	}
}

func TestChainToSpec_DefaultOrg(t *testing.T) {
	t.Parallel()
	specs, err := ChainToSpec([]int{1, 1}, "", "", "")
	if err != nil {
		t.Fatalf("ChainToSpec() err = %v", err)
	}
	if specs[0].CommonName != "Certtool Root CA" {
		t.Errorf("root CN = %q, want %q", specs[0].CommonName, "Certtool Root CA")
	}
	if specs[0].Children[0].CommonName != "Certtool" {
		t.Errorf("leaf CN = %q, want %q", specs[0].Children[0].CommonName, "Certtool")
	}
}

func TestChainToSpec_Breadth(t *testing.T) {
	t.Parallel()
	specs, err := ChainToSpec([]int{1, 2, 3}, "", "Acme", "")
	if err != nil {
		t.Fatalf("ChainToSpec() err = %v", err)
	}
	if len(specs) != 1 {
		t.Fatalf("got %d roots, want 1", len(specs))
	}
	root := specs[0]
	if root.CommonName != "Acme Root CA" {
		t.Errorf("root CN = %q", root.CommonName)
	}
	if len(root.Children) != 2 {
		t.Fatalf("root has %d children, want 2", len(root.Children))
	}
	for i, inter := range root.Children {
		if !inter.CertificateAuthority {
			t.Errorf("intermediate %d CA = false", i)
		}
		if len(inter.Children) != 3 {
			t.Fatalf("intermediate %d has %d children, want 3", i, len(inter.Children))
		}
		for _, leaf := range inter.Children {
			if leaf.CertificateAuthority {
				t.Errorf("leaf %q CA = true", leaf.CommonName)
			}
		}
	}
}

func TestChainToSpec_MultipleRoots(t *testing.T) {
	t.Parallel()
	specs, err := ChainToSpec([]int{2, 1}, "", "Org", "")
	if err != nil {
		t.Fatalf("ChainToSpec() err = %v", err)
	}
	if len(specs) != 2 {
		t.Fatalf("got %d roots, want 2", len(specs))
	}
	if specs[0].CommonName != "Org Root CA 1" {
		t.Errorf("root 0 CN = %q", specs[0].CommonName)
	}
	if specs[1].CommonName != "Org Root CA 2" {
		t.Errorf("root 1 CN = %q", specs[1].CommonName)
	}
}

func TestChainToSpec_ZeroWidth(t *testing.T) {
	t.Parallel()
	for _, widths := range [][]int{{0}, {1, 0, 3}, {-2}} {
		if _, err := ChainToSpec(widths, "", "", ""); err == nil {
			t.Errorf("ChainToSpec(%v) = nil error, want error", widths)
		}
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

	if results[1].CertPath != filepath.Join(outputDir, "frontend.crt") {
		t.Errorf("frontend path = %q", results[1].CertPath)
	}
	if results[2].CertPath != filepath.Join(outputDir, "backend.crt") {
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

// Specs built in code skip UnmarshalSpec, so GenerateFromSpec must reject a
// filename that leaves the output directory before it writes anything, even
// the output directory itself.
func TestGenerateFromSpec_FilenameOutsideOutputDir(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	outputDir := filepath.Join(root, "out", "certs")
	specs := []CertificateSpec{
		{
			CommonName:           testSpecRootCA,
			CertificateAuthority: true,
			KeyType:              "ECDSA-256",
			Filename:             "root",
			Children: []CertificateSpec{
				{CommonName: "leaf", KeyType: "ECDSA-256", Filename: "../../escaped"},
			},
		},
	}

	_, err := GenerateFromSpec(specs, outputDir)
	if err == nil || !strings.Contains(err.Error(), "must be a file name") {
		t.Fatalf("GenerateFromSpec() err = %v, want a filename error", err)
	}
	for _, path := range []string{filepath.Join(root, "escaped.crt"), filepath.Join(root, "escaped.key"), outputDir} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("%s exists (stat err = %v), want nothing written", path, err)
		}
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
		{file: "yubikey-intermediate.yaml", wantCerts: 5},
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

func TestChainToSpec_SingleWidthProducesLeaves(t *testing.T) {
	t.Parallel()
	specs, err := ChainToSpec([]int{3}, "svc", "Org", "")
	if err != nil {
		t.Fatalf("ChainToSpec() err = %v", err)
	}
	if len(specs) != 3 {
		t.Fatalf("got %d certificates, want 3", len(specs))
	}
	for i, spec := range specs {
		if want := fmt.Sprintf("svc %d", i+1); spec.CommonName != want {
			t.Errorf("certificate %d CN = %q, want %q", i, spec.CommonName, want)
		}
		if spec.CertificateAuthority || len(spec.Children) != 0 {
			t.Errorf("certificate %d = %+v, want a standalone leaf", i, spec)
		}
	}

	single, err := ChainToSpec([]int{1}, "", "Org", "")
	if err != nil {
		t.Fatalf("ChainToSpec([1]) err = %v", err)
	}
	if len(single) != 1 || single[0].CommonName != "Org" || single[0].CertificateAuthority {
		t.Errorf("ChainToSpec([1]) = %+v, want one leaf named %q", single, "Org")
	}
}

// collectNames returns the common names of the whole hierarchy in the same
// shape as the spec tree, one slice per layer, in depth-first order.
func collectNames(specs []CertificateSpec, layers [][]string, depth int) [][]string {
	for i := range specs {
		for len(layers) <= depth {
			layers = append(layers, nil)
		}
		layers[depth] = append(layers[depth], specs[i].CommonName)
		layers = collectNames(specs[i].Children, layers, depth+1)
	}
	return layers
}

func TestChainToSpec_LineageNames(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		widths []int
		want   [][]string // common names per layer, depth-first order
	}{
		{
			name:   "single root and intermediate number only the leaves",
			widths: []int{1, 1, 3},
			want: [][]string{
				{"Org Root CA"},
				{"Org Intermediate CA"},
				{"svc 1", "svc 2", "svc 3"},
			},
		},
		{
			name:   "singular root omits its number and leaves carry the intermediate",
			widths: []int{1, 2, 2},
			want: [][]string{
				{"Org Root CA"},
				{"Org Intermediate CA 1", "Org Intermediate CA 2"},
				{"svc 1.1", "svc 1.2", "svc 2.1", "svc 2.2"},
			},
		},
		{
			name:   "multiple roots number every descendant with its lineage",
			widths: []int{2, 2, 1},
			want: [][]string{
				{"Org Root CA 1", "Org Root CA 2"},
				{"Org Intermediate CA 1.1", "Org Intermediate CA 1.2", "Org Intermediate CA 2.1", "Org Intermediate CA 2.2"},
				{"svc 1.1", "svc 1.2", "svc 2.1", "svc 2.2"},
			},
		},
		{
			name:   "singular layers below a branch inherit the ancestor number",
			widths: []int{2, 1, 1},
			want: [][]string{
				{"Org Root CA 1", "Org Root CA 2"},
				{"Org Intermediate CA 1", "Org Intermediate CA 2"},
				{"svc 1", "svc 2"},
			},
		},
		{
			name:   "multiple intermediate tiers declare their depth",
			widths: []int{1, 1, 1, 1},
			want: [][]string{
				{"Org Root CA"},
				{"Org Intermediate 1 CA"},
				{"Org Intermediate 2 CA"},
				{"svc"},
			},
		},
		{
			name:   "tier label precedes the lineage",
			widths: []int{1, 2, 2, 1},
			want: [][]string{
				{"Org Root CA"},
				{"Org Intermediate 1 CA 1", "Org Intermediate 1 CA 2"},
				{"Org Intermediate 2 CA 1.1", "Org Intermediate 2 CA 1.2", "Org Intermediate 2 CA 2.1", "Org Intermediate 2 CA 2.2"},
				{"svc 1.1", "svc 1.2", "svc 2.1", "svc 2.2"},
			},
		},
		{
			name:   "fully branching hierarchy",
			widths: []int{2, 2, 2},
			want: [][]string{
				{"Org Root CA 1", "Org Root CA 2"},
				{"Org Intermediate CA 1.1", "Org Intermediate CA 1.2", "Org Intermediate CA 2.1", "Org Intermediate CA 2.2"},
				{"svc 1.1.1", "svc 1.1.2", "svc 1.2.1", "svc 1.2.2", "svc 2.1.1", "svc 2.1.2", "svc 2.2.1", "svc 2.2.2"},
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			specs, err := ChainToSpec(tc.widths, "svc", "Org", "")
			if err != nil {
				t.Fatalf("ChainToSpec(%v) err = %v", tc.widths, err)
			}
			got := collectNames(specs, nil, 0)
			if len(got) != len(tc.want) {
				t.Fatalf("got %d layers, want %d: %v", len(got), len(tc.want), got)
			}
			for layer := range tc.want {
				if !slices.Equal(got[layer], tc.want[layer]) {
					t.Errorf("layer %d names = %q, want %q", layer, got[layer], tc.want[layer])
				}
			}
		})
	}
}

// TestChainToSpec_NamesUnique checks the reason for lineage and tier labels:
// no two certificates in a generated hierarchy may share a common name.
func TestChainToSpec_NamesUnique(t *testing.T) {
	t.Parallel()
	for _, widths := range [][]int{{2, 1}, {3, 2, 2}, {1, 3, 1}, {2, 2, 2, 2}, {1, 1, 4}, {1, 1, 1, 1, 1}, {2, 1, 3, 1}, {5}} {
		specs, err := ChainToSpec(widths, "svc", "Org", "")
		if err != nil {
			t.Fatalf("ChainToSpec(%v) err = %v", widths, err)
		}
		seen := map[string]bool{}
		for layer, names := range collectNames(specs, nil, 0) {
			for _, name := range names {
				if seen[name] {
					t.Errorf("widths %v: layer %d repeats common name %q", widths, layer, name)
				}
				seen[name] = true
			}
		}
	}
}

func TestChainToSpec_RejectsCollidingCommonName(t *testing.T) {
	t.Parallel()
	for _, cn := range []string{"Org Root CA", "Org Intermediate CA"} {
		if _, err := ChainToSpec([]int{1, 1, 1}, cn, "Org", ""); err == nil {
			t.Errorf("ChainToSpec with common name %q = nil error, want a uniqueness error", cn)
		}
	}
}

func TestChainToSpec_NamePrefix(t *testing.T) {
	t.Parallel()
	for _, widths := range [][]int{{3}, {1, 1}, {1, 2, 3}, {2, 1, 1, 2}} {
		plain, err := ChainToSpec(widths, "svc", "Org", "")
		if err != nil {
			t.Fatalf("ChainToSpec(%v) err = %v", widths, err)
		}
		prefixed, err := ChainToSpec(widths, "svc", "Org", "prod")
		if err != nil {
			t.Fatalf("ChainToSpec(%v, prefix) err = %v", widths, err)
		}

		want := collectNames(plain, nil, 0)
		got := collectNames(prefixed, nil, 0)
		if len(got) != len(want) {
			t.Fatalf("widths %v: got %d layers, want %d", widths, len(got), len(want))
		}
		for layer := range want {
			for i := range want[layer] {
				if expected := "prod " + want[layer][i]; got[layer][i] != expected {
					t.Errorf("widths %v: layer %d name = %q, want %q", widths, layer, got[layer][i], expected)
				}
			}
		}
	}
}

func TestChainToSpec_BlankNamePrefixIsEmpty(t *testing.T) {
	t.Parallel()
	plain, err := ChainToSpec([]int{1, 1}, "svc", "Org", "")
	if err != nil {
		t.Fatalf("ChainToSpec() err = %v", err)
	}
	blank, err := ChainToSpec([]int{1, 1}, "svc", "Org", "  ")
	if err != nil {
		t.Fatalf("ChainToSpec() err = %v", err)
	}
	if plain[0].CommonName != blank[0].CommonName || plain[0].Children[0].CommonName != blank[0].Children[0].CommonName {
		t.Errorf("blank prefix changed names: %q/%q vs %q/%q",
			blank[0].CommonName, blank[0].Children[0].CommonName, plain[0].CommonName, plain[0].Children[0].CommonName)
	}
}

func TestGenerateFromSpec_PFXPasswordEnv(t *testing.T) {
	specs := []CertificateSpec{{CommonName: "Sign", CodeSigning: true, PFXPasswordEnv: "CERTTOOL_TEST_PFX_PASSWORD", Filename: "sign"}} //nolint:gosec // An environment variable name, not a credential.

	t.Setenv("CERTTOOL_TEST_PFX_PASSWORD", "")
	_, err := GenerateFromSpec(specs, t.TempDir())
	if err == nil || !strings.Contains(err.Error(), `spec "Sign" reads its .pfx password from the environment variable CERTTOOL_TEST_PFX_PASSWORD, which is not set`) {
		t.Errorf("GenerateFromSpec() without the variable err = %v, want a not set error", err)
	}

	t.Setenv("CERTTOOL_TEST_PFX_PASSWORD", "from-env")
	out, err := GenerateFromSpec(specs, t.TempDir())
	if err != nil {
		t.Fatalf("GenerateFromSpec() err = %v", err)
	}
	if _, _, err := pkcs12.Decode(out[0].KeyPair.PFX, "from-env"); err != nil {
		t.Errorf("pkcs12.Decode() with the environment password err = %v", err)
	}
}

func TestReplacePFXPasswords(t *testing.T) {
	t.Parallel()
	specs := []CertificateSpec{
		{CommonName: "a", PFXPassword: "x"},
		{CommonName: "ca", CertificateAuthority: true, Children: []CertificateSpec{{CommonName: "b", PFXPassword: "y"}, {CommonName: "c"}}},
	}
	if diff := cmp.Diff([]string{"a", "b"}, SpecsWithPFXPassword(specs)); diff != "" {
		t.Errorf("SpecsWithPFXPassword() mismatch (-want +got):\n%s", diff)
	}

	ReplacePFXPasswords(specs, "PW")
	data, err := MarshalSpec(specs)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "pfxPassword:") || strings.Count(string(data), "pfxPasswordEnv: PW") != 2 {
		t.Errorf("MarshalSpec() after ReplacePFXPasswords =\n%s\nwant two pfxPasswordEnv entries and no passwords", data)
	}
	if got := SpecsWithPFXPassword(specs); len(got) != 0 {
		t.Errorf("SpecsWithPFXPassword() after replacing = %v, want none", got)
	}
}

func TestSpecsWithUnprotectedPFX(t *testing.T) {
	t.Parallel()
	specs := []CertificateSpec{
		{CommonName: "default target", CodeSigning: true},
		{CommonName: "windows7", CodeSigning: true, Target: "win7"},
		{CommonName: "password", CodeSigning: true, PFXPassword: "x"},
		{CommonName: "password env", CodeSigning: true, PFXPasswordEnv: "PW"},
		{CommonName: "linux", CodeSigning: true, Target: "linux"},
		{CommonName: "tls", CertificateAuthority: true, Children: []CertificateSpec{{CommonName: "leaf"}}},
	}
	if diff := cmp.Diff([]string{"default target", "windows7"}, SpecsWithUnprotectedPFX(specs)); diff != "" {
		t.Errorf("SpecsWithUnprotectedPFX() mismatch (-want +got):\n%s", diff)
	}
}

// Spec CAs are limited to the depth of the hierarchy the spec describes,
// unless maxPathLen says otherwise.
func TestGenerateFromSpec_PathLength(t *testing.T) {
	t.Parallel()
	unlimited := -1
	specs, err := ChainToSpec([]int{1, 1, 1}, "leaf", "Acme", "")
	if err != nil {
		t.Fatal(err)
	}
	specs = append(specs, CertificateSpec{CommonName: "Open CA", CertificateAuthority: true, MaxPathLen: &unlimited})
	for i := range specs {
		specs[i].KeyType = testSpecECDSA256
	}
	specs[0].Children[0].KeyType = testSpecECDSA256
	specs[0].Children[0].Children[0].KeyType = testSpecECDSA256

	out, err := GenerateFromSpec(specs, t.TempDir())
	if err != nil {
		t.Fatalf("GenerateFromSpec() err = %v", err)
	}
	got := map[string]int{}
	for _, o := range out {
		block, _ := pem.Decode(o.KeyPair.PublicCertificate)
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		if cert.IsCA {
			got[o.CommonName] = cert.MaxPathLen
		}
	}
	want := map[string]int{"Acme Root CA": 1, "Acme Intermediate CA": 0, "Open CA": -1}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("path lengths mismatch (-want +got):\n%s", diff)
	}
}

func TestGenerateFromSpec_NameConstraints(t *testing.T) {
	t.Parallel()
	data := []byte(`- commonName: Internal CA
  certificateAuthority: true
  keyType: ECDSA-256
  permittedDNSDomains: [internal.example.com]
  permittedIPRanges: [10.0.0.0/8]
  children:
    - commonName: api
      keyType: ECDSA-256
      hostnames: [api.internal.example.com, 10.0.0.5]
`)
	specs, err := UnmarshalSpec(data)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := GenerateFromSpec(specs, t.TempDir()); err != nil {
		t.Fatalf("GenerateFromSpec() err = %v", err)
	}

	specs[0].Children[0].Hostnames = []string{"api.example.org"}
	if _, err := GenerateFromSpec(specs, t.TempDir()); err == nil || !strings.Contains(err.Error(), `reject the name "api.example.org"`) {
		t.Errorf("GenerateFromSpec() with a name outside the constraints err = %v, want a name constraint error", err)
	}
}

func TestGenerateFromSpec_EmailAndSSH(t *testing.T) {
	t.Parallel()
	specs, err := UnmarshalSpec([]byte(`
- commonName: CA
  certificateAuthority: true
  keyType: ECDSA-256
  children:
    - commonName: Alice
      keyType: ECDSA-256
      emailAddresses: [alice@example.com]
      sshPublicKey: true
      filename: alice
    - commonName: server.example.com
      keyType: ECDSA-256
      hostnames: [server.example.com]
`))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	out, err := GenerateFromSpec(specs, dir)
	if err != nil {
		t.Fatal(err)
	}
	ca, alice, server := parseGenCert(t, out[0]), parseGenCert(t, out[1]), parseGenCert(t, out[2])
	if !slices.Contains(ca.ExtKeyUsage, x509.ExtKeyUsageEmailProtection) {
		t.Errorf("CA extended key usages = %v, want email protection for the certificate below it", ca.ExtKeyUsage)
	}
	if !slices.Equal(alice.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection, x509.ExtKeyUsageClientAuth}) {
		t.Errorf("person extended key usages = %v, want email protection and TLS client", alice.ExtKeyUsage)
	}
	if !slices.Equal(alice.EmailAddresses, []string{"alice@example.com"}) || len(alice.DNSNames)+len(alice.IPAddresses) > 0 {
		t.Errorf("person names = %v %v %v, want only alice@example.com", alice.EmailAddresses, alice.DNSNames, alice.IPAddresses)
	}
	if slices.Contains(server.ExtKeyUsage, x509.ExtKeyUsageEmailProtection) {
		t.Error("a TLS certificate got email protection")
	}

	want := filepath.Join(dir, "alice.key.pub")
	if out[1].SSHPublicKeyPath != want || out[2].SSHPublicKeyPath != "" {
		t.Errorf("SSHPublicKeyPath = %q, %q; want %q and none", out[1].SSHPublicKeyPath, out[2].SSHPublicKeyPath, want)
	}
	data, err := os.ReadFile(filepath.Clean(want))
	if err != nil {
		t.Fatal(err)
	}
	pub, comment, _, _, err := ssh.ParseAuthorizedKey(data)
	if err != nil {
		t.Fatalf("ParseAuthorizedKey() err = %v", err)
	}
	sshPub, err := ssh.NewPublicKey(alice.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pub.Marshal(), sshPub.Marshal()) || comment != "alice@example.com" {
		t.Errorf("SSH public key = %s %q, want the certificate's key and the email address", pub.Type(), comment)
	}
}

// TestGenerateFromSpec_SSHPublicKeyComment checks that a common name cannot
// add lines or fields to the .key.pub file, which is appended to
// authorized_keys.
func TestGenerateFromSpec_SSHPublicKeyComment(t *testing.T) {
	t.Parallel()
	specs, err := UnmarshalSpec([]byte(`
- commonName: "alice\nssh-ed25519\tAAAAC3NzaC1lZDI1NTE5AAAAIA attacker\r"
  keyType: ECDSA-256
  sshPublicKey: true
  filename: alice
`))
	if err != nil {
		t.Fatal(err)
	}
	out, err := GenerateFromSpec(specs, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Clean(out[0].SSHPublicKeyPath))
	if err != nil {
		t.Fatal(err)
	}
	if lines := bytes.Count(data, []byte("\n")); lines != 1 || bytes.ContainsRune(data, '\r') {
		t.Fatalf(".key.pub = %q, want one line", data)
	}
	_, comment, _, rest, err := ssh.ParseAuthorizedKey(data)
	if err != nil {
		t.Fatalf("ParseAuthorizedKey() err = %v", err)
	}
	if want := "alice_ssh-ed25519_AAAAC3NzaC1lZDI1NTE5AAAAIA_attacker_"; comment != want || len(rest) > 0 {
		t.Errorf("comment = %q, rest = %q; want %q and nothing else", comment, rest, want)
	}
}

func TestGenerateFromSpec_ReusedCAWithoutEmailProtection(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	ca := "- commonName: CA\n  certificateAuthority: true\n  keyType: ECDSA-256\n  children:\n    - commonName: server\n      keyType: ECDSA-256\n"
	specs, err := UnmarshalSpec([]byte(ca))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := GenerateFromSpec(specs, dir); err != nil {
		t.Fatal(err)
	}
	specs, err = UnmarshalSpec([]byte(ca + "    - commonName: Alice\n      emailAddresses: [alice@example.com]\n"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = GenerateFromSpec(specs, dir)
	if !errors.Is(err, ErrExistingFiles) || !strings.Contains(err.Error(), "does not allow email protection") {
		t.Errorf("GenerateFromSpec() err = %v, want one saying the CA does not allow email protection", err)
	}
}
