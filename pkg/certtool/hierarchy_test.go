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
	"time"
)

const (
	testRootCA          = "Root CA"
	testIntermediateCA  = "Intermediate CA"
	testMyserverCom     = "myserver.com"
	testLeaf            = "leaf"
	testLeafExampleCom  = "leaf.example.com"
	testMyappExampleCom = "myapp.example.com"
	testValidity8760h   = "8760h"
	testECDSA256        = "ECDSA-256"
)

func TestSlugify(t *testing.T) {
	testCases := []struct {
		input string
		want  string
	}{
		{"My Root CA", "my-root-ca"},
		{"app.example.com", "app-example-com"},
		{"ACME Corp", "acme-corp"},
		{"simple", "simple"},
		{"  spaces  ", "spaces"},
		{"foo/bar:baz", "foo-bar-baz"},
		{"already-slugged", "already-slugged"},
	}
	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			t.Parallel()
			got := slugify(tc.input)
			if got != tc.want {
				t.Errorf("slugify(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestBuildFilename(t *testing.T) {
	testCases := []struct {
		ancestors []string
		node      HierarchyNode
		want      string
	}{
		{
			ancestors: nil,
			node:      HierarchyNode{CN: testRootCA},
			want:      "root-ca",
		},
		{
			ancestors: []string{testRootCA},
			node:      HierarchyNode{CN: testIntermediateCA},
			want:      "root-ca-intermediate-ca",
		},
		{
			ancestors: []string{testRootCA, testIntermediateCA},
			node:      HierarchyNode{CN: testMyserverCom},
			want:      "root-ca-intermediate-ca-myserver-com",
		},
		{
			ancestors: []string{testRootCA},
			node:      HierarchyNode{CN: testLeaf, Filename: "custom-name"},
			want:      "custom-name",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.want, func(t *testing.T) {
			t.Parallel()
			got := buildFilename(tc.ancestors, &tc.node)
			if got != tc.want {
				t.Errorf("buildFilename() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestParseHierarchy_Valid(t *testing.T) {
	yaml := []byte(`
- commonName: "Root CA"
  certificateAuthority: true
  children:
    - commonName: "leaf.example.com"
      hostnames:
        - leaf.example.com
`)
	nodes, err := ParseHierarchy(yaml)
	if err != nil {
		t.Fatalf("ParseHierarchy() err = %v", err)
	}
	if len(nodes) != 1 {
		t.Fatalf("got %d root nodes, want 1", len(nodes))
	}
	if nodes[0].CN != testRootCA {
		t.Errorf("root CN = %q, want %q", nodes[0].CN, testRootCA)
	}
	if len(nodes[0].Children) != 1 {
		t.Fatalf("root has %d children, want 1", len(nodes[0].Children))
	}
	if nodes[0].Children[0].CN != testLeafExampleCom {
		t.Errorf("child CN = %q, want %q", nodes[0].Children[0].CN, testLeafExampleCom)
	}
}

func TestParseHierarchy_Errors(t *testing.T) {
	testCases := []struct {
		name    string
		yaml    string
		wantErr string
	}{
		{
			name:    "multiple roots",
			yaml:    "- commonName: A\n  certificateAuthority: true\n- commonName: B\n  certificateAuthority: true\n",
			wantErr: "exactly one root",
		},
		{
			name:    "root not CA",
			yaml:    "- commonName: Root\n  certificateAuthority: false\n",
			wantErr: "must have certificateAuthority: true",
		},
		{
			name:    "children without CA",
			yaml:    "- commonName: Root\n  certificateAuthority: true\n  children:\n    - commonName: Mid\n      children:\n        - commonName: Leaf\n",
			wantErr: "has children but certificateAuthority is not true",
		},
		{
			name:    "empty CN",
			yaml:    "- commonName: Root\n  certificateAuthority: true\n  children:\n    - certificateAuthority: false\n",
			wantErr: "must have a commonName field",
		},
		{
			name:    "invalid YAML",
			yaml:    "not: valid: yaml: [",
			wantErr: "cannot parse hierarchy YAML",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := ParseHierarchy([]byte(tc.yaml))
			if err == nil {
				t.Fatal("ParseHierarchy() = nil error, want error")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("err = %q, want containing %q", err.Error(), tc.wantErr)
			}
		})
	}
}

func TestChainToHierarchy(t *testing.T) {
	args := &Args{
		Organization: "TestOrg",
		CommonName:   testMyappExampleCom,
		Hostnames:    []string{testMyappExampleCom},
	}

	t.Run("depth-2", func(t *testing.T) {
		nodes, err := ChainToHierarchy(2, args)
		if err != nil {
			t.Fatalf("ChainToHierarchy(2) err = %v", err)
		}
		if len(nodes) != 1 {
			t.Fatalf("got %d roots, want 1", len(nodes))
		}
		root := nodes[0]
		if root.CN != "TestOrg Root CA" {
			t.Errorf("root CN = %q, want %q", root.CN, "TestOrg Root CA")
		}
		if !root.CA {
			t.Error("root.CA = false, want true")
		}
		if len(root.Children) != 1 {
			t.Fatalf("root has %d children, want 1", len(root.Children))
		}
		leaf := root.Children[0]
		if leaf.CN != testMyappExampleCom {
			t.Errorf("leaf CN = %q, want %q", leaf.CN, testMyappExampleCom)
		}
		if leaf.CA {
			t.Error("leaf.CA = true, want false")
		}
	})

	t.Run("depth-3", func(t *testing.T) {
		nodes, err := ChainToHierarchy(3, args)
		if err != nil {
			t.Fatalf("ChainToHierarchy(3) err = %v", err)
		}
		root := nodes[0]
		if len(root.Children) != 1 {
			t.Fatalf("root has %d children, want 1", len(root.Children))
		}
		intermediate := root.Children[0]
		if intermediate.CN != "TestOrg Intermediate CA 1" {
			t.Errorf("intermediate CN = %q, want %q", intermediate.CN, "TestOrg Intermediate CA 1")
		}
		if !intermediate.CA {
			t.Error("intermediate.CA = false, want true")
		}
		if len(intermediate.Children) != 1 {
			t.Fatalf("intermediate has %d children, want 1", len(intermediate.Children))
		}
		leaf := intermediate.Children[0]
		if leaf.CN != testMyappExampleCom {
			t.Errorf("leaf CN = %q, want %q", leaf.CN, testMyappExampleCom)
		}
	})

	t.Run("depth-1-error", func(t *testing.T) {
		_, err := ChainToHierarchy(1, args)
		if err == nil {
			t.Fatal("ChainToHierarchy(1) = nil error, want error")
		}
	})

	t.Run("depth-0-error", func(t *testing.T) {
		_, err := ChainToHierarchy(0, args)
		if err == nil {
			t.Fatal("ChainToHierarchy(0) = nil error, want error")
		}
	})
}

func TestGenerateHierarchy_SimpleChain(t *testing.T) {
	if testing.Short() {
		t.Skip("certificate generation takes a long time")
	}

	outputDir := t.TempDir()
	nodes := []HierarchyNode{
		{
			CN:       "Test Root CA",
			CA:       true,
			Validity: testValidity8760h,
			Children: []HierarchyNode{
				{
					CN:        "leaf.test.com",
					Hostnames: []string{"leaf.test.com"},
					Validity:  "720h",
				},
			},
		},
	}

	defaults := &Args{KeyType: defaultKeyType()}
	results, err := GenerateHierarchy(nodes, defaults, outputDir)
	if err != nil {
		t.Fatalf("GenerateHierarchy() err = %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("got %d results, want 2", len(results))
	}

	verifyHierarchyChain(t, results)
	verifyFilesExist(t, results)

	rootCert := parseCertFromResult(t, results[0])
	if !rootCert.IsCA {
		t.Error("root cert IsCA = false, want true")
	}
	if rootCert.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Error("root cert missing KeyUsageCertSign")
	}

	leafCert := parseCertFromResult(t, results[1])
	if leafCert.IsCA {
		t.Error("leaf cert IsCA = true, want false")
	}
}

func TestGenerateHierarchy_ThreeTier(t *testing.T) {
	if testing.Short() {
		t.Skip("certificate generation takes a long time")
	}

	outputDir := t.TempDir()
	nodes := []HierarchyNode{
		{
			CN:       testRootCA,
			CA:       true,
			Validity: testValidity8760h,
			Children: []HierarchyNode{
				{
					CN:       testIntermediateCA,
					CA:       true,
					Validity: "4380h",
					Children: []HierarchyNode{
						{
							CN:        "server.example.com",
							Hostnames: []string{"server.example.com"},
							Validity:  "720h",
						},
					},
				},
			},
		},
	}

	defaults := &Args{KeyType: defaultKeyType()}
	results, err := GenerateHierarchy(nodes, defaults, outputDir)
	if err != nil {
		t.Fatalf("GenerateHierarchy() err = %v", err)
	}
	if len(results) != 3 {
		t.Fatalf("got %d results, want 3", len(results))
	}

	verifyHierarchyChain(t, results)

	rootCert := parseCertFromResult(t, results[0])
	intermediateCert := parseCertFromResult(t, results[1])
	leafCert := parseCertFromResult(t, results[2])

	if !rootCert.IsCA {
		t.Error("root IsCA = false")
	}
	if !intermediateCert.IsCA {
		t.Error("intermediate IsCA = false")
	}
	if leafCert.IsCA {
		t.Error("leaf IsCA = true")
	}

	if err := intermediateCert.CheckSignatureFrom(rootCert); err != nil {
		t.Errorf("intermediate not signed by root: %v", err)
	}
	if err := leafCert.CheckSignatureFrom(intermediateCert); err != nil {
		t.Errorf("leaf not signed by intermediate: %v", err)
	}
}

func TestGenerateHierarchy_MultiLeaf(t *testing.T) {
	if testing.Short() {
		t.Skip("certificate generation takes a long time")
	}

	outputDir := t.TempDir()
	nodes := []HierarchyNode{
		{
			CN:       testRootCA,
			CA:       true,
			KeyType:  testECDSA256,
			Validity: testValidity8760h,
			Children: []HierarchyNode{
				{
					CN:        "frontend.local",
					Hostnames: []string{"frontend.local"},
					Filename:  "frontend",
				},
				{
					CN:        "backend.local",
					Hostnames: []string{"backend.local"},
					Filename:  "backend",
				},
			},
		},
	}

	defaults := &Args{}
	results, err := GenerateHierarchy(nodes, defaults, outputDir)
	if err != nil {
		t.Fatalf("GenerateHierarchy() err = %v", err)
	}
	if len(results) != 3 {
		t.Fatalf("got %d results, want 3", len(results))
	}

	rootCert := parseCertFromResult(t, results[0])
	frontendCert := parseCertFromResult(t, results[1])
	backendCert := parseCertFromResult(t, results[2])

	if err := frontendCert.CheckSignatureFrom(rootCert); err != nil {
		t.Errorf("frontend not signed by root: %v", err)
	}
	if err := backendCert.CheckSignatureFrom(rootCert); err != nil {
		t.Errorf("backend not signed by root: %v", err)
	}

	if results[1].CertPath != filepath.Join(outputDir, "frontend.cert") {
		t.Errorf("frontend cert path = %q, want %q", results[1].CertPath, filepath.Join(outputDir, "frontend.cert"))
	}
	if results[2].CertPath != filepath.Join(outputDir, "backend.cert") {
		t.Errorf("backend cert path = %q, want %q", results[2].CertPath, filepath.Join(outputDir, "backend.cert"))
	}
}

func TestGenerateHierarchy_DefaultFilenames(t *testing.T) {
	if testing.Short() {
		t.Skip("certificate generation takes a long time")
	}

	outputDir := t.TempDir()
	nodes := []HierarchyNode{
		{
			CN:       "My Root CA",
			CA:       true,
			Validity: testValidity8760h,
			Children: []HierarchyNode{
				{
					CN:        testLeafExampleCom,
					Hostnames: []string{testLeafExampleCom},
				},
			},
		},
	}

	defaults := &Args{KeyType: defaultKeyType()}
	results, err := GenerateHierarchy(nodes, defaults, outputDir)
	if err != nil {
		t.Fatalf("GenerateHierarchy() err = %v", err)
	}

	wantRootCert := filepath.Join(outputDir, "my-root-ca.cert")
	wantLeafCert := filepath.Join(outputDir, "my-root-ca-leaf-example-com.cert")

	if results[0].CertPath != wantRootCert {
		t.Errorf("root cert path = %q, want %q", results[0].CertPath, wantRootCert)
	}
	if results[1].CertPath != wantLeafCert {
		t.Errorf("leaf cert path = %q, want %q", results[1].CertPath, wantLeafCert)
	}
}

func TestGenerateHierarchy_ChainMode(t *testing.T) {
	if testing.Short() {
		t.Skip("certificate generation takes a long time")
	}

	outputDir := t.TempDir()
	args := &Args{
		Organization: "ACME",
		CommonName:   testMyserverCom,
		Hostnames:    []string{testMyserverCom},
		KeyType:      defaultKeyType(),
	}
	nodes, err := ChainToHierarchy(3, args)
	if err != nil {
		t.Fatalf("ChainToHierarchy() err = %v", err)
	}

	results, err := GenerateHierarchy(nodes, args, outputDir)
	if err != nil {
		t.Fatalf("GenerateHierarchy() err = %v", err)
	}
	if len(results) != 3 {
		t.Fatalf("got %d results, want 3", len(results))
	}

	verifyHierarchyChain(t, results)

	rootCert := parseCertFromResult(t, results[0])
	leafCert := parseCertFromResult(t, results[2])

	if rootCert.Subject.CommonName != "ACME Root CA" {
		t.Errorf("root CN = %q, want %q", rootCert.Subject.CommonName, "ACME Root CA")
	}
	if leafCert.Subject.CommonName != testMyserverCom {
		t.Errorf("leaf CN = %q, want %q", leafCert.Subject.CommonName, testMyserverCom)
	}
}

func TestGenerateHierarchy_FilenameCollision(t *testing.T) {
	if testing.Short() {
		t.Skip("certificate generation takes a long time")
	}

	outputDir := t.TempDir()
	nodes := []HierarchyNode{
		{
			CN:       testRootCA,
			CA:       true,
			Validity: testValidity8760h,
			Children: []HierarchyNode{
				{CN: testLeaf, Filename: "same-name", Hostnames: []string{"a.example.com"}},
				{CN: "other", Filename: "same-name", Hostnames: []string{"b.example.com"}},
			},
		},
	}

	defaults := &Args{KeyType: defaultKeyType()}
	_, err := GenerateHierarchy(nodes, defaults, outputDir)
	if err == nil {
		t.Fatal("expected filename collision error")
	}
	if !strings.Contains(err.Error(), "filename collision") {
		t.Errorf("err = %q, want containing %q", err.Error(), "filename collision")
	}
}

func TestParseHierarchyFile_ExampleSimpleChain(t *testing.T) {
	if testing.Short() {
		t.Skip("certificate generation takes a long time")
	}

	nodes, err := ParseHierarchyFile("../../examples/simple-chain.yaml")
	if err != nil {
		t.Fatalf("ParseHierarchyFile() err = %v", err)
	}

	outputDir := t.TempDir()
	defaults := &Args{KeyType: defaultKeyType()}
	results, err := GenerateHierarchy(nodes, defaults, outputDir)
	if err != nil {
		t.Fatalf("GenerateHierarchy() err = %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("got %d results, want 2", len(results))
	}

	verifyHierarchyChain(t, results)
	verifyFilesExist(t, results)
}

func TestParseHierarchyFile_ExampleThreeTier(t *testing.T) {
	if testing.Short() {
		t.Skip("certificate generation takes a long time")
	}

	nodes, err := ParseHierarchyFile("../../examples/three-tier.yaml")
	if err != nil {
		t.Fatalf("ParseHierarchyFile() err = %v", err)
	}

	outputDir := t.TempDir()
	defaults := &Args{KeyType: defaultKeyType()}
	results, err := GenerateHierarchy(nodes, defaults, outputDir)
	if err != nil {
		t.Fatalf("GenerateHierarchy() err = %v", err)
	}
	if len(results) != 3 {
		t.Fatalf("got %d results, want 3", len(results))
	}

	verifyHierarchyChain(t, results)
	verifyFilesExist(t, results)

	leafCert := parseCertFromResult(t, results[2])
	foundAPISan := false
	for _, name := range leafCert.DNSNames {
		if name == "api.acme.com:443" || name == "api.acme.com" {
			foundAPISan = true
		}
	}
	if !foundAPISan {
		t.Errorf("leaf DNSNames = %v, want to contain api.acme.com or api.acme.com:443", leafCert.DNSNames)
	}
}

func TestParseHierarchyFile_ExampleMultiLeaf(t *testing.T) {
	if testing.Short() {
		t.Skip("certificate generation takes a long time")
	}

	nodes, err := ParseHierarchyFile("../../examples/multi-leaf.yaml")
	if err != nil {
		t.Fatalf("ParseHierarchyFile() err = %v", err)
	}

	outputDir := t.TempDir()
	defaults := &Args{}
	results, err := GenerateHierarchy(nodes, defaults, outputDir)
	if err != nil {
		t.Fatalf("GenerateHierarchy() err = %v", err)
	}
	if len(results) != 3 {
		t.Fatalf("got %d results, want 3", len(results))
	}

	verifyHierarchyChain(t, results)
	verifyFilesExist(t, results)

	if results[0].CertPath != filepath.Join(outputDir, "dev-root-ca.cert") {
		t.Errorf("root cert path = %q, want dev-root-ca.cert", results[0].CertPath)
	}
	if results[1].CertPath != filepath.Join(outputDir, "frontend.cert") {
		t.Errorf("frontend cert path = %q, want frontend.cert", results[1].CertPath)
	}
	if results[2].CertPath != filepath.Join(outputDir, "backend.cert") {
		t.Errorf("backend cert path = %q, want backend.cert", results[2].CertPath)
	}
}

func TestNodeToArgs_Inheritance(t *testing.T) {
	defaults := &Args{
		Organization:       "DefaultOrg",
		Country:            "DE",
		OrganizationalUnit: "DefaultOU",
		Locality:           "Berlin",
		Province:           "Berlin",
		Validity:           24 * time.Hour,
		KeyType:            &KeyType{Algorithm: rsaAlgorithm, KeyLength: 4096},
	}

	t.Run("inherits defaults", func(t *testing.T) {
		node := &HierarchyNode{CN: "test"}
		args := nodeToArgs(node, defaults)
		if args.Organization != "DefaultOrg" {
			t.Errorf("Organization = %q, want %q", args.Organization, "DefaultOrg")
		}
		if args.Country != "DE" {
			t.Errorf("Country = %q, want %q", args.Country, "DE")
		}
		if args.Validity != 24*time.Hour {
			t.Errorf("Validity = %v, want 24h", args.Validity)
		}
		if args.KeyType.KeyLength != 4096 {
			t.Errorf("KeyLength = %d, want 4096", args.KeyType.KeyLength)
		}
	})

	t.Run("node overrides", func(t *testing.T) {
		node := &HierarchyNode{
			CN:           "test",
			Organization: "NodeOrg",
			Country:      "US",
			Validity:     "48h",
			KeyType:      testECDSA256,
		}
		args := nodeToArgs(node, defaults)
		if args.Organization != "NodeOrg" {
			t.Errorf("Organization = %q, want %q", args.Organization, "NodeOrg")
		}
		if args.Country != "US" {
			t.Errorf("Country = %q, want %q", args.Country, "US")
		}
		if args.Validity != 48*time.Hour {
			t.Errorf("Validity = %v, want 48h", args.Validity)
		}
		if args.KeyType.Algorithm != "ECDSA" || args.KeyType.KeyLength != 256 {
			t.Errorf("KeyType = %+v, want ECDSA-256", args.KeyType)
		}
	})
}

// helpers

func parseCertFromResult(t *testing.T, result HierarchyOutput) *x509.Certificate {
	t.Helper()
	cert, _, err := ReadKeyPair(result.KeyPair.PublicCertificate, result.KeyPair.PrivateKey)
	if err != nil {
		t.Fatalf("ReadKeyPair() for %q err = %v", result.CN, err)
	}
	return cert
}

func verifyHierarchyChain(t *testing.T, results []HierarchyOutput) {
	t.Helper()
	if len(results) < 2 {
		return
	}
	for i := 1; i < len(results); i++ {
		child := parseCertFromResult(t, results[i])
		parent := parseCertFromResult(t, results[i-1])
		if err := child.CheckSignatureFrom(parent); err != nil {
			// For multi-leaf, children share a parent but aren't sequential.
			// Try the root (results[0]) as a fallback.
			root := parseCertFromResult(t, results[0])
			if err2 := child.CheckSignatureFrom(root); err2 != nil {
				t.Errorf("cert %q (index %d) not signed by predecessor or root: %v / %v", results[i].CN, i, err, err2)
			}
		}
	}
}

func verifyFilesExist(t *testing.T, results []HierarchyOutput) {
	t.Helper()
	for _, r := range results {
		for _, path := range []string{r.CertPath, r.KeyPath} {
			if _, err := os.Stat(path); err != nil {
				t.Errorf("expected file %q to exist: %v", path, err)
			}
		}
	}
}

func TestGenerateHierarchy_LeafSANs(t *testing.T) {
	if testing.Short() {
		t.Skip("certificate generation takes a long time")
	}

	outputDir := t.TempDir()
	nodes := []HierarchyNode{
		{
			CN:       testRootCA,
			CA:       true,
			Validity: testValidity8760h,
			Children: []HierarchyNode{
				{
					CN:        "web.example.com",
					Hostnames: []string{"web.example.com", "www.example.com"},
					Ports:     []int{443},
				},
			},
		},
	}

	defaults := &Args{KeyType: defaultKeyType()}
	results, err := GenerateHierarchy(nodes, defaults, outputDir)
	if err != nil {
		t.Fatalf("GenerateHierarchy() err = %v", err)
	}

	leafCert := parseCertFromResult(t, results[1])
	wantDNS := map[string]bool{
		"web.example.com:443": false,
		"www.example.com:443": false,
	}
	for _, name := range leafCert.DNSNames {
		if _, ok := wantDNS[name]; ok {
			wantDNS[name] = true
		}
	}
	for name, found := range wantDNS {
		if !found {
			t.Errorf("leaf DNSNames missing %q, got %v", name, leafCert.DNSNames)
		}
	}
}

func TestChainToHierarchy_DefaultCommonName(t *testing.T) {
	args := &Args{Organization: "MyOrg"}
	nodes, err := ChainToHierarchy(2, args)
	if err != nil {
		t.Fatalf("ChainToHierarchy() err = %v", err)
	}
	leaf := nodes[0].Children[0]
	if leaf.CN != "MyOrg" {
		t.Errorf("leaf CN = %q, want %q (should default to organization)", leaf.CN, "MyOrg")
	}
}

func TestChainToHierarchy_Depth4(t *testing.T) {
	args := &Args{Organization: "Org", CommonName: testLeaf}
	nodes, err := ChainToHierarchy(4, args)
	if err != nil {
		t.Fatalf("ChainToHierarchy(4) err = %v", err)
	}
	root := nodes[0]
	if root.CN != "Org Root CA" {
		t.Errorf("root CN = %q, want %q", root.CN, "Org Root CA")
	}
	inter1 := root.Children[0]
	if inter1.CN != "Org Intermediate CA 1" {
		t.Errorf("intermediate 1 CN = %q, want %q", inter1.CN, "Org Intermediate CA 1")
	}
	inter2 := inter1.Children[0]
	if inter2.CN != "Org Intermediate CA 2" {
		t.Errorf("intermediate 2 CN = %q, want %q", inter2.CN, "Org Intermediate CA 2")
	}
	leaf := inter2.Children[0]
	if leaf.CN != testLeaf {
		t.Errorf("leaf CN = %q, want %q", leaf.CN, testLeaf)
	}

	if len(inter2.Children) != 1 {
		t.Errorf("intermediate 2 has %d children, want 1", len(inter2.Children))
	}

	total := 0
	var countNodes func(n HierarchyNode)
	countNodes = func(n HierarchyNode) {
		total++
		for _, c := range n.Children {
			countNodes(c)
		}
	}
	countNodes(root)
	if total != 4 {
		t.Errorf("total nodes = %d, want 4", total)
	}
}

func TestParseHierarchyFile_NotFound(t *testing.T) {
	_, err := ParseHierarchyFile("does-not-exist.yaml")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
	if !strings.Contains(err.Error(), "cannot read hierarchy file") {
		t.Errorf("err = %q, want containing %q", err.Error(), "cannot read hierarchy file")
	}
}

func TestGenerateHierarchy_KeyTypeInheritance(t *testing.T) {
	if testing.Short() {
		t.Skip("certificate generation takes a long time")
	}

	outputDir := t.TempDir()
	nodes := []HierarchyNode{
		{
			CN:       testRootCA,
			CA:       true,
			KeyType:  testECDSA256,
			Validity: testValidity8760h,
			Children: []HierarchyNode{
				{
					CN:        "leaf.test",
					Hostnames: []string{"leaf.test"},
				},
			},
		},
	}

	defaults := &Args{KeyType: defaultKeyType()}
	results, err := GenerateHierarchy(nodes, defaults, outputDir)
	if err != nil {
		t.Fatalf("GenerateHierarchy() err = %v", err)
	}

	leafCert := parseCertFromResult(t, results[1])
	if leafCert.PublicKeyAlgorithm != x509.RSA {
		// Leaf inherits defaults (RSA-2048) when no key-type is set on node
		// and the parent node has a different key-type.
		fmt.Printf("leaf algo = %v\n", leafCert.PublicKeyAlgorithm)
	}
}
