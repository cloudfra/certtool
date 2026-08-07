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
	"regexp"
	"strings"
	"time"

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

// ChainToSpec builds a certificate hierarchy from a list of layer widths.
//
// A single-element widths (e.g. [5]) is shorthand for a linear chain of that
// depth (equivalent to [1,1,1,1,1]).
//
// With multiple elements, each value is the number of certificates at that
// layer: widths[0] roots, widths[1] intermediates per root, and so on. The
// last layer produces leaf certificates; all prior layers are CAs.
//
// Example: [1,2,3] produces 1 root CA, 2 intermediate CAs (each signed by
// the root), and 3 leaves per intermediate (6 leaves total, 9 certificates).
func ChainToSpec(widths []int, commonName string, organization string) ([]CertificateSpec, error) {
	if len(widths) == 0 {
		return nil, fmt.Errorf("--chain requires at least one value")
	}

	if len(widths) == 1 {
		depth := widths[0]
		if depth < 2 {
			return nil, fmt.Errorf("--chain must be at least 2 (root CA + leaf), got %d", depth)
		}
		expanded := make([]int, depth)
		for i := range expanded {
			expanded[i] = 1
		}
		widths = expanded
	}

	if len(widths) < 2 {
		return nil, fmt.Errorf("--chain must have at least 2 layers (root + leaf)")
	}

	for i, w := range widths {
		if w < 1 {
			return nil, fmt.Errorf("--chain layer %d must be at least 1, got %d", i+1, w)
		}
	}

	if organization == "" {
		organization = "Certtool"
	}

	leafCN := commonName
	if leafCN == "" {
		leafCN = organization
	}

	roots := make([]CertificateSpec, widths[0])
	for i := range roots {
		cn := fmt.Sprintf("%s Root CA", organization)
		if widths[0] > 1 {
			cn = fmt.Sprintf("%s Root CA %d", organization, i+1)
		}
		roots[i] = CertificateSpec{
			CommonName:           cn,
			CertificateAuthority: true,
		}
		roots[i].Children = buildChainLayer(widths, 1, leafCN, organization)
	}

	return roots, nil
}

func buildChainLayer(widths []int, depth int, leafCN string, organization string) []CertificateSpec {
	if depth >= len(widths) {
		return nil
	}

	isLeaf := depth == len(widths)-1
	count := widths[depth]
	specs := make([]CertificateSpec, count)

	for i := range specs {
		if isLeaf {
			cn := leafCN
			if count > 1 {
				cn = fmt.Sprintf("%s %d", leafCN, i+1)
			}
			specs[i] = CertificateSpec{CommonName: cn}
		} else {
			cn := fmt.Sprintf("%s Intermediate CA %d", organization, i+1)
			if count == 1 {
				cn = fmt.Sprintf("%s Intermediate CA", organization)
			}
			specs[i] = CertificateSpec{
				CommonName:           cn,
				CertificateAuthority: true,
				Children:             buildChainLayer(widths, depth+1, leafCN, organization),
			}
		}
	}

	return specs
}

// GenerationOutput is the result of generating a single certificate from a spec.
type GenerationOutput struct {
	// CommonName is the CN of the generated certificate.
	CommonName string
	// KeyPair holds the generated public certificate, private key, and optional PFX data.
	KeyPair *KeyPair
	// CertPath is the filesystem path where the public certificate was written.
	CertPath string
	// KeyPath is the filesystem path where the private key was written.
	KeyPath string
	// PFXPath is the filesystem path where the PKCS#12 bundle was written.
	// Empty when the certificate does not produce PFX output.
	PFXPath string
}

// GenerateFromSpec generates certificates for all specs and writes them to outputDir.
func GenerateFromSpec(specs []CertificateSpec, outputDir string) ([]GenerationOutput, error) {
	if err := os.MkdirAll(outputDir, 0o750); err != nil {
		return nil, fmt.Errorf("cannot create output directory (%s): %w", outputDir, err)
	}

	filenames := map[string]string{}
	var results []GenerationOutput

	for i := range specs {
		out, err := generateSpec(&specs[i], nil, outputDir, nil, filenames)
		if err != nil {
			return nil, err
		}
		results = append(results, out...)
	}
	return results, nil
}

var slugPattern = regexp.MustCompile(`[^a-z0-9]+`)

func slugify(s string) string {
	s = strings.ToLower(s)
	s = slugPattern.ReplaceAllString(s, "-")
	s = strings.Trim(s, "-")
	return s
}

func specFilename(ancestorCNs []string, spec *CertificateSpec) string {
	if spec.Filename != "" {
		return spec.Filename
	}
	parts := make([]string, 0, len(ancestorCNs)+1)
	for _, cn := range ancestorCNs {
		parts = append(parts, slugify(cn))
	}
	parts = append(parts, slugify(spec.CommonName))
	return strings.Join(parts, "-")
}

func generateSpec(spec *CertificateSpec, parentKP *KeyPair, outputDir string, ancestorCNs []string, filenames map[string]string) ([]GenerationOutput, error) {
	args := specToArgs(spec)
	args.ParentKeyPair = parentKP

	kp, err := GenerateKeyPair(args)
	if err != nil {
		return nil, fmt.Errorf("cannot generate certificate for %q: %w", spec.CommonName, err)
	}

	basename := specFilename(ancestorCNs, spec)
	certPath := filepath.Join(outputDir, basename+".cert")
	keyPath := filepath.Join(outputDir, basename+".key")

	if existingCN, ok := filenames[basename]; ok {
		return nil, fmt.Errorf("filename collision: %q and %q both resolve to %q", existingCN, spec.CommonName, basename)
	}
	filenames[basename] = spec.CommonName

	if err := WriteKeyPair(kp, certPath, keyPath); err != nil {
		return nil, fmt.Errorf("cannot write certificate for %q: %w", spec.CommonName, err)
	}

	output := GenerationOutput{
		CommonName: spec.CommonName,
		KeyPair:    kp,
		CertPath:   certPath,
		KeyPath:    keyPath,
	}

	if len(kp.PFX) > 0 {
		pfxPath := filepath.Join(outputDir, basename+".pfx")
		if err := WritePFX(kp, pfxPath); err != nil {
			return nil, fmt.Errorf("cannot write PFX for %q: %w", spec.CommonName, err)
		}
		output.PFXPath = pfxPath
	}

	results := []GenerationOutput{output}

	childAncestors := append(append([]string{}, ancestorCNs...), spec.CommonName)
	for i := range spec.Children {
		childResults, err := generateSpec(&spec.Children[i], kp, outputDir, childAncestors, filenames)
		if err != nil {
			return nil, err
		}
		results = append(results, childResults...)
	}

	return results, nil
}

func specToArgs(spec *CertificateSpec) *Args {
	args := &Args{
		CA:                 spec.CertificateAuthority,
		CodeSigning:        spec.CodeSigning,
		Target:             spec.Target,
		PFXPassword:        spec.PFXPassword,
		CommonName:         spec.CommonName,
		Organization:       spec.Organization,
		OrganizationalUnit: spec.OrganizationalUnit,
		Country:            spec.Country,
		Locality:           spec.Locality,
		Province:           spec.Province,
		Hostnames:          spec.Hostnames,
		Ports:              spec.Ports,
	}

	if spec.Validity != "" {
		if d, err := time.ParseDuration(spec.Validity); err == nil {
			args.Validity = d
		}
	}

	if spec.KeyType != "" {
		parts := strings.SplitN(strings.ToUpper(spec.KeyType), "-", 2)
		if len(parts) == 2 {
			var keyLen int
			if _, err := fmt.Sscanf(parts[1], "%d", &keyLen); err == nil {
				args.KeyType = &KeyType{Algorithm: parts[0], KeyLength: keyLen}
			}
		} else if len(parts) == 1 {
			args.KeyType = &KeyType{Algorithm: parts[0]}
		}
	}

	return args
}
