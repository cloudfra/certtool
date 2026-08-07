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
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// CertificateSpec defines a certificate to generate. Specs form a tree: each
// spec may have children that are signed by the parent certificate. A YAML
// spec file is a list of top-level CertificateSpec nodes; multiple top-level
// entries produce disjoint certificate trees in a single generation pass.
type CertificateSpec struct {
	// CommonName is the subject common name (CN) of the certificate.
	// Every spec must have a non-empty common name.
	CommonName string `yaml:"commonName"`

	// CertificateAuthority marks this certificate as a CA. CA certificates
	// can sign child certificates and receive KeyUsageCertSign. Any spec
	// with Children must set this to true.
	CertificateAuthority bool `yaml:"certificateAuthority,omitempty"`

	// CodeSigning generates a code signing certificate instead of a TLS
	// certificate. Code signing certs use ExtKeyUsageCodeSigning and omit
	// SANs. On Windows targets a PKCS#12 (.pfx) bundle is also produced.
	CodeSigning bool `yaml:"codeSigning,omitempty"`

	// Target selects the platform profile for code signing certificates.
	// Valid values: "windows7" (aliases: "win7", "windows8", "win8"),
	// "windows10" (alias: "win10"), "windows11" (alias: "win11"), "linux".
	// Defaults to "windows10" when empty and CodeSigning is true.
	// Ignored when CodeSigning is false.
	Target string `yaml:"target,omitempty"`

	// PFXPassword sets the password on the PKCS#12 (.pfx) bundle produced
	// for code signing certificates on Windows targets. An empty string
	// means no password. Ignored when CodeSigning is false or the target
	// does not produce PFX output.
	PFXPassword string `yaml:"pfxPassword,omitempty"`

	// KeyType specifies the key algorithm and size as "ALGORITHM-BITS",
	// for example "RSA-2048", "RSA-4096", "ECDSA-256", "ECDSA-384".
	// When empty, defaults are applied: for code signing certificates the
	// target profile selects the key type; for TLS certificates the CLI
	// default (RSA-2048) is used.
	KeyType string `yaml:"keyType,omitempty"`

	// Validity is how long the certificate is valid, as a Go duration
	// string (e.g. "8760h" for one year, "87600h" for ten years).
	// When empty, the CLI default (8760h) is applied.
	Validity string `yaml:"validity,omitempty"`

	// Organization is the subject organization (O) field.
	Organization string `yaml:"organization,omitempty"`

	// OrganizationalUnit is the subject organizational unit (OU) field.
	OrganizationalUnit string `yaml:"organizationalUnit,omitempty"`

	// Country is the subject country (C) field (e.g. "US", "DE", "GB").
	Country string `yaml:"country,omitempty"`

	// Locality is the subject locality (L) field, typically a city name.
	Locality string `yaml:"locality,omitempty"`

	// Province is the subject state or province (ST) field.
	Province string `yaml:"province,omitempty"`

	// Hostnames lists DNS names and IP addresses added as Subject
	// Alternative Names (SANs). Entries may include a port suffix
	// (e.g. "app.example.com:443"); entries without ports are expanded
	// against the Ports list.
	Hostnames []string `yaml:"hostnames,omitempty"`

	// Ports lists port numbers applied to every hostname that does not
	// already specify a port. For example, hostnames ["app.example.com"]
	// with ports [443, 8443] produces SANs "app.example.com:443" and
	// "app.example.com:8443".
	Ports []int `yaml:"ports,omitempty"`

	// Filename overrides the default output filename (without extension).
	// By default filenames are derived from the slugified common name path
	// through the tree (e.g. "root-ca-leaf-example-com").
	Filename string `yaml:"filename,omitempty"`

	// Children are certificate specs signed by this certificate. This spec
	// must have CertificateAuthority set to true when Children is non-empty.
	Children []CertificateSpec `yaml:"children,omitempty"`
}

// ReadSpec reads and validates a YAML certificate spec from a file.
func ReadSpec(path string) ([]CertificateSpec, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("cannot read spec file (%s): %w", path, err)
	}
	return UnmarshalSpec(data)
}

// UnmarshalSpec parses and validates a YAML certificate spec from bytes.
func UnmarshalSpec(data []byte) ([]CertificateSpec, error) {
	var specs []CertificateSpec
	if err := yaml.Unmarshal(data, &specs); err != nil {
		return nil, fmt.Errorf("cannot parse spec YAML: %w", err)
	}

	if len(specs) == 0 {
		return nil, fmt.Errorf("spec must have at least one certificate")
	}

	for i := range specs {
		if err := validateSpec(&specs[i]); err != nil {
			return nil, err
		}
	}

	return specs, nil
}

func validateSpec(spec *CertificateSpec) error {
	if spec.CommonName == "" {
		return fmt.Errorf("every certificate spec must have a commonName")
	}
	if len(spec.Children) > 0 && !spec.CertificateAuthority {
		return fmt.Errorf("spec %q has children but certificateAuthority is not true", spec.CommonName)
	}
	for i := range spec.Children {
		if err := validateSpec(&spec.Children[i]); err != nil {
			return err
		}
	}
	return nil
}

// MarshalSpec serializes certificate specs to YAML.
func MarshalSpec(specs []CertificateSpec) ([]byte, error) {
	return yaml.Marshal(specs)
}
