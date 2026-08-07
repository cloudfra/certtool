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
	"strings"
	"testing"
)

const (
	testSpecRootCA  = "Root CA"
	testSpecLeafCom = "leaf.example.com"
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
	if specs[1].Target != "windows10" {
		t.Errorf("second spec Target = %q, want %q", specs[1].Target, "windows10")
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
	if s.Target != "windows10" {
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
