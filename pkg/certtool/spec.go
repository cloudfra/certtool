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
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
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

	// PFXPasswordEnv names an environment variable that holds the PKCS#12
	// password, so the spec file does not have to contain it. The variable
	// must be set and not empty. Mutually exclusive with PFXPassword.
	PFXPasswordEnv string `yaml:"pfxPasswordEnv,omitempty"`

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
	// Alternative Names (SANs). A port suffix (e.g. "app.example.com:443")
	// is removed, because SANs cannot hold ports.
	Hostnames []string `yaml:"hostnames,omitempty"`

	// Filename overrides the default output filename (without extension).
	// By default filenames are derived from the slugified common name path
	// through the tree (e.g. "root-ca-leaf-example-com"). It must be a plain
	// file name: no directories, "..", or absolute paths, so every file stays
	// in the output directory.
	Filename string `yaml:"filename,omitempty"`

	// MaxPathLen limits how many CAs may sit below this CA. When not set it
	// is the number of CA levels below this one in the spec, so the CA can
	// sign exactly the hierarchy the spec describes. -1 means no limit.
	MaxPathLen *int `yaml:"maxPathLen,omitempty"`

	// PermittedDNSDomains limits the DNS names certificates below this CA may
	// hold: "example.com" permits it and its subdomains, ".example.com" only
	// its subdomains.
	PermittedDNSDomains []string `yaml:"permittedDNSDomains,omitempty"`

	// PermittedIPRanges limits the IP addresses certificates below this CA
	// may hold, in CIDR notation such as "10.0.0.0/8".
	PermittedIPRanges []string `yaml:"permittedIPRanges,omitempty"`

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
	if err := validateFilename(spec); err != nil {
		return err
	}
	if spec.PFXPassword != "" && spec.PFXPasswordEnv != "" {
		return fmt.Errorf("spec %q sets both pfxPassword and pfxPasswordEnv; keep only pfxPasswordEnv", spec.CommonName)
	}
	for _, hostname := range spec.Hostnames {
		if err := ValidateHostname(hostname); err != nil {
			return fmt.Errorf("spec %q: %w", spec.CommonName, err)
		}
	}
	if !spec.CertificateAuthority && (spec.MaxPathLen != nil || len(spec.PermittedDNSDomains) > 0 || len(spec.PermittedIPRanges) > 0) {
		return fmt.Errorf("spec %q sets maxPathLen, permittedDNSDomains, or permittedIPRanges, which only apply to a CA; set certificateAuthority: true", spec.CommonName)
	}
	if spec.MaxPathLen != nil && *spec.MaxPathLen < -1 {
		return fmt.Errorf("spec %q has maxPathLen %d; use 0 or more, or -1 for no limit", spec.CommonName, *spec.MaxPathLen)
	}
	if _, err := ParseIPRanges(spec.PermittedIPRanges); err != nil {
		return fmt.Errorf("spec %q: %w", spec.CommonName, err)
	}
	for i := range spec.Children {
		child := &spec.Children[i]
		// A CA's extended key usage limits what it can issue, so a TLS CA
		// cannot sign code signing certificates and the reverse.
		if child.CodeSigning != spec.CodeSigning {
			return fmt.Errorf("spec %q has codeSigning %t but its parent %q has codeSigning %t; clients reject a certificate whose purpose its CA does not allow, so make code signing certificates top-level entries", child.CommonName, child.CodeSigning, spec.CommonName, spec.CodeSigning)
		}
		if err := validateSpec(child); err != nil {
			return err
		}
	}
	return nil
}

// validateFilename returns an error unless the spec's filename is empty or a
// single file name, so the files it names cannot be written outside the
// output directory.
func validateFilename(spec *CertificateSpec) error {
	if spec.Filename == "" {
		return nil
	}
	if strings.ContainsAny(spec.Filename, `/\`) || !filepath.IsLocal(spec.Filename) {
		return fmt.Errorf("spec %q has filename %q, which must be a file name without directories, \"..\", or an absolute path", spec.CommonName, spec.Filename)
	}
	return nil
}

// validateFilenames runs validateFilename on every spec in the tree.
func validateFilenames(specs []CertificateSpec) error {
	for i := range specs {
		if err := validateFilename(&specs[i]); err != nil {
			return err
		}
		if err := validateFilenames(specs[i].Children); err != nil {
			return err
		}
	}
	return nil
}

// SpecsWithPFXPassword returns the common names of the specs in the tree that
// hold a .pfx password in plain text in pfxPassword.
func SpecsWithPFXPassword(specs []CertificateSpec) []string {
	var names []string
	for i := range specs {
		if specs[i].PFXPassword != "" {
			names = append(names, specs[i].CommonName)
		}
		names = append(names, SpecsWithPFXPassword(specs[i].Children)...)
	}
	return names
}

// SpecsWithLegacyPFX returns the common names of the code signing specs in the
// tree whose target writes a legacy .pfx (3DES with a SHA-1 MAC), which is far
// easier to brute-force than the default.
func SpecsWithLegacyPFX(specs []CertificateSpec) []string {
	var names []string
	for i := range specs {
		if profile, err := GetProfile(specs[i].Target); err == nil && specs[i].CodeSigning && profile.LegacyPFX {
			names = append(names, specs[i].CommonName)
		}
		names = append(names, SpecsWithLegacyPFX(specs[i].Children)...)
	}
	return names
}

// SpecsWithUnprotectedPFX returns the common names of the specs in the tree
// that produce a .pfx bundle without a password, which anyone who can read
// the file can use to sign code.
func SpecsWithUnprotectedPFX(specs []CertificateSpec) []string {
	var names []string
	for i := range specs {
		s := &specs[i]
		target := s.Target
		if target == "" {
			target = windows10Target
		}
		if profile, err := GetProfile(target); err == nil && s.CodeSigning && profile.OutputPFX && s.PFXPassword == "" && s.PFXPasswordEnv == "" {
			names = append(names, s.CommonName)
		}
		names = append(names, SpecsWithUnprotectedPFX(s.Children)...)
	}
	return names
}

// ReplacePFXPasswords replaces every plain text pfxPassword in the tree with
// pfxPasswordEnv set to env, so the spec can be written out without the
// passwords.
func ReplacePFXPasswords(specs []CertificateSpec, env string) {
	for i := range specs {
		if specs[i].PFXPassword != "" {
			specs[i].PFXPassword = ""
			specs[i].PFXPasswordEnv = env
		}
		ReplacePFXPasswords(specs[i].Children, env)
	}
}

// caDepth returns how many levels of CAs the spec tree has below spec.
func caDepth(spec *CertificateSpec) int {
	depth := 0
	for i := range spec.Children {
		if child := &spec.Children[i]; child.CertificateAuthority {
			depth = max(depth, 1+caDepth(child))
		}
	}
	return depth
}

// ParseIPRanges parses IP ranges in CIDR notation, such as "10.0.0.0/8".
func ParseIPRanges(ranges []string) ([]*net.IPNet, error) {
	parsed := make([]*net.IPNet, 0, len(ranges))
	for _, r := range ranges {
		_, ipNet, err := net.ParseCIDR(strings.TrimSpace(r))
		if err != nil {
			return nil, fmt.Errorf("permitted IP range %q is not in CIDR notation such as 10.0.0.0/8: %w", r, err)
		}
		parsed = append(parsed, ipNet)
	}
	return parsed, nil
}

// MarshalSpec serializes certificate specs to YAML.
func MarshalSpec(specs []CertificateSpec) ([]byte, error) {
	return yaml.Marshal(specs)
}

// ChainToSpec builds a certificate hierarchy from a list of layer widths.
//
// Each value is the number of certificates at that layer: widths[0] roots,
// widths[1] intermediates per root, and so on. The last layer produces leaf
// certificates; all prior layers are CAs. A single value therefore has no CA
// layers and produces that many standalone leaf certificates.
//
// Examples:
//   - [3] produces 3 standalone leaf certificates.
//   - [1,1] produces 1 root CA and 1 leaf.
//   - [1,2,3] produces 1 root CA, 2 intermediate CAs (each signed by the
//     root), and 3 leaves per intermediate (6 leaves, 9 certificates total).
//
// commonName is the leaf common name. When empty it defaults to organization,
// which in turn defaults to "Certtool", so every certificate always has a name.
//
// namePrefix, when not blank, is placed in front of every certificate's common
// name, separated by a space ("prod Org Root CA"). It defaults to empty.
//
// Every certificate in the result has a unique common name; ChainToSpec
// returns an error if commonName would collide with a generated CA name.
//
// Intermediates declare their depth when there is more than one intermediate
// tier: "Org Intermediate 1 CA", "Org Intermediate 2 CA", and so on. With a
// single tier the number is left out ("Org Intermediate CA").
//
// Common names also carry a dot-delimited lineage so certificates from
// adjacent trees are distinguishable. The lineage lists the 1-based position within
// each layer that has more than one certificate, from the root down to the
// certificate itself. Layers with a single certificate add nothing, so [1,1,3]
// numbers only the leaves ("svc 1"), while [1,2,3] names the leaves "svc 1.1",
// "svc 1.2", "svc 1.3", "svc 2.1", and so on.
func ChainToSpec(widths []int, commonName string, organization string, namePrefix string) ([]CertificateSpec, error) {
	if len(widths) == 0 {
		return nil, fmt.Errorf("--chain requires at least one value")
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

	specs := buildChainLayer(widths, 0, nil, leafCN, organization)
	applyNamePrefix(specs, strings.TrimSpace(namePrefix))
	if err := checkUniqueNames(specs, map[string]bool{}); err != nil {
		return nil, err
	}
	return specs, nil
}

// applyNamePrefix prepends prefix and a space to every common name in the spec
// tree. An empty prefix leaves the names unchanged.
func applyNamePrefix(specs []CertificateSpec, prefix string) {
	if prefix == "" {
		return
	}
	for i := range specs {
		specs[i].CommonName = prefix + " " + specs[i].CommonName
		applyNamePrefix(specs[i].Children, prefix)
	}
}

// checkUniqueNames returns an error if a common name appears more than once
// in the spec tree. seen accumulates the names visited so far.
func checkUniqueNames(specs []CertificateSpec, seen map[string]bool) error {
	for i := range specs {
		if seen[specs[i].CommonName] {
			return fmt.Errorf("--chain would generate the common name %q more than once; choose a different --common-name or --organization", specs[i].CommonName)
		}
		seen[specs[i].CommonName] = true
		if err := checkUniqueNames(specs[i].Children, seen); err != nil {
			return err
		}
	}
	return nil
}

// caName returns the base common name, before any lineage, of a CA at the given
// layer of a hierarchy with the given number of layers. Layer 0 is the root;
// layers 1 through layers-2 are intermediate tiers. The tier number is only
// included when there is more than one tier, so it is empty by default.
func caName(organization string, layer, layers int) string {
	if layer == 0 {
		return organization + " Root CA"
	}
	tier := ""
	if layers-2 > 1 {
		tier = " " + strconv.Itoa(layer)
	}
	return organization + " Intermediate" + tier + " CA"
}

// nextLineage extends the lineage of a parent with the 1-based position of a
// child among count siblings. A layer with a single certificate is omitted
// because the position would carry no information.
func nextLineage(parent []int, count, index int) []int {
	if count == 1 {
		return parent
	}
	return append(slices.Clone(parent), index+1)
}

// lineageName appends a dot-delimited lineage to a base name, if there is one.
func lineageName(base string, lineage []int) string {
	if len(lineage) == 0 {
		return base
	}
	parts := make([]string, len(lineage))
	for i, n := range lineage {
		parts[i] = strconv.Itoa(n)
	}
	return base + " " + strings.Join(parts, ".")
}

// buildChainLayer builds the certificates at the given layer, and recursively
// the layers beneath them. Layer 0 is the root layer unless it is also the
// leaf layer.
func buildChainLayer(widths []int, layer int, parentLineage []int, leafCN string, organization string) []CertificateSpec {
	isLeaf := layer == len(widths)-1
	count := widths[layer]
	specs := make([]CertificateSpec, count)

	for i := range specs {
		lineage := nextLineage(parentLineage, count, i)
		if isLeaf {
			specs[i] = CertificateSpec{CommonName: lineageName(leafCN, lineage)}
			continue
		}

		specs[i] = CertificateSpec{
			CommonName:           lineageName(caName(organization, layer, len(widths)), lineage),
			CertificateAuthority: true,
			Children:             buildChainLayer(widths, layer+1, lineage, leafCN, organization),
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
	// Reused is set when the certificate and key already existed in the
	// output directory and were kept instead of generated.
	Reused bool
}

// ErrExistingFiles marks errors about certificate files in the output
// directory that cannot be reused.
var ErrExistingFiles = errors.New("existing certificate files cannot be reused")

// SpecOptions controls GenerateFromSpecWithOptions.
type SpecOptions struct {
	// Issuer, when not nil, signs the top-level specs, so every tree chains
	// to it instead of being self-signed.
	Issuer *Issuer
	// Overwrite regenerates every certificate and key, replacing the files
	// in the output directory. By default a certificate whose files already
	// exist is reused, so a spec can be extended without resetting the
	// hierarchy it describes.
	Overwrite bool
	// Encryption, when not nil, encrypts the private key and .pfx files
	// written, and decrypts the encrypted keys of reused certificates.
	Encryption *KeyEncryption
}

// GenerateFromSpec generates certificates for all specs and writes them to
// outputDir, reusing certificates whose files already exist there.
func GenerateFromSpec(specs []CertificateSpec, outputDir string) ([]GenerationOutput, error) {
	return GenerateFromSpecWithOptions(specs, outputDir, SpecOptions{})
}

// GenerateFromSpecWithIssuer is GenerateFromSpec with the top-level specs
// signed by issuer.
func GenerateFromSpecWithIssuer(specs []CertificateSpec, outputDir string, issuer *Issuer) ([]GenerationOutput, error) {
	return GenerateFromSpecWithOptions(specs, outputDir, SpecOptions{Issuer: issuer})
}

// GenerateFromSpecWithOptions generates certificates for all specs and writes
// them to outputDir.
//
// Unless opts.Overwrite is set, a certificate whose certificate and key files
// already exist is reused, and only the certificates that are missing are
// generated, signed by their reused or new parents. A reused certificate must
// still fit the spec and the hierarchy: its key must match it, its common name
// and CA flag must match the spec, it must not have expired, and it must be
// signed by its parent. Otherwise the error wraps ErrExistingFiles.
func GenerateFromSpecWithOptions(specs []CertificateSpec, outputDir string, opts SpecOptions) ([]GenerationOutput, error) {
	// Specs built in code skip UnmarshalSpec, so check every filename before
	// anything is generated or written.
	if err := validateFilenames(specs); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(outputDir, 0o750); err != nil {
		return nil, fmt.Errorf("cannot create output directory (%s): %w", outputDir, err)
	}

	filenames := map[string]string{}
	var results []GenerationOutput

	for i := range specs {
		out, err := generateSpec(&specs[i], nil, opts.Issuer, outputDir, nil, filenames, &opts)
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

func generateSpec(spec *CertificateSpec, parentKP *KeyPair, issuer *Issuer, outputDir string, ancestorCNs []string, filenames map[string]string, opts *SpecOptions) ([]GenerationOutput, error) {
	basename := specFilename(ancestorCNs, spec)
	certPath := filepath.Join(outputDir, basename+".crt")
	keyPath := filepath.Join(outputDir, basename+".key")
	pfxPath := filepath.Join(outputDir, basename+".pfx")

	if existingCN, ok := filenames[basename]; ok {
		return nil, fmt.Errorf("filename collision: %q and %q both resolve to %q", existingCN, spec.CommonName, basename)
	}
	filenames[basename] = spec.CommonName

	args := specToArgs(spec)
	args.ParentKeyPair = parentKP
	args.Issuer = issuer
	if spec.PFXPasswordEnv != "" {
		password := os.Getenv(spec.PFXPasswordEnv)
		if password == "" {
			return nil, fmt.Errorf("spec %q reads its .pfx password from the environment variable %s, which is not set", spec.CommonName, spec.PFXPasswordEnv)
		}
		args.PFXPassword = password
	}
	if spec.CertificateAuthority {
		pathLen := caDepth(spec)
		if spec.MaxPathLen != nil {
			pathLen = *spec.MaxPathLen
		}
		if pathLen >= 0 {
			args.MaxPathLen = &pathLen
		}
		ranges, err := ParseIPRanges(spec.PermittedIPRanges)
		if err != nil {
			return nil, fmt.Errorf("spec %q: %w", spec.CommonName, err)
		}
		args.PermittedDNSDomains = spec.PermittedDNSDomains
		args.PermittedIPRanges = ranges
	}

	enc := opts.Encryption
	var kp *KeyPair
	reused := false
	if !opts.Overwrite {
		var err error
		kp, keyPath, err = reuseKeyPair(spec, args, certPath, keyPath, pfxPath, enc)
		if err != nil {
			return nil, err
		}
		reused = kp != nil
	}
	if !reused {
		var err error
		kp, err = GenerateKeyPair(args)
		if err != nil {
			return nil, fmt.Errorf("cannot generate certificate for %q: %w", spec.CommonName, err)
		}
		if opts.Overwrite {
			// Remove the other form of the key, so the output directory never
			// holds a stale key next to the new one.
			if err := removeOtherForm(keyPath, enc); err != nil {
				return nil, err
			}
			if err := removeOtherForm(pfxPath, enc); err != nil {
				return nil, err
			}
		}
		if keyPath, err = enc.WriteKeyPair(kp, certPath, keyPath); err != nil {
			return nil, fmt.Errorf("cannot write certificate for %q: %w", spec.CommonName, err)
		}
	}

	output := GenerationOutput{
		CommonName: spec.CommonName,
		KeyPair:    kp,
		CertPath:   certPath,
		KeyPath:    keyPath,
		Reused:     reused,
	}

	if len(kp.PFX) > 0 {
		existing, err := existingPrivateFile(pfxPath)
		if err != nil {
			return nil, err
		}
		if !reused || existing == "" {
			if existing, err = enc.WritePFX(kp, pfxPath); err != nil {
				return nil, fmt.Errorf("cannot write PFX for %q: %w", spec.CommonName, err)
			}
		}
		output.PFXPath = existing
	}

	results := []GenerationOutput{output}

	childAncestors := append(append([]string{}, ancestorCNs...), spec.CommonName)
	for i := range spec.Children {
		childResults, err := generateSpec(&spec.Children[i], kp, nil, outputDir, childAncestors, filenames, opts)
		if err != nil {
			return nil, err
		}
		results = append(results, childResults...)
	}

	return results, nil
}

// reuseKeyPair returns the key pair already in certPath and keyPath, or nil
// when neither file exists. The pair must still fit spec and its place in the
// hierarchy described by args; anything else is an error wrapping
// ErrExistingFiles, because reusing it would break the chain or ignore the
// spec. For a code signing spec whose .pfx is missing, the .pfx is rebuilt
// from the reused key.
func reuseKeyPair(spec *CertificateSpec, args *Args, certPath, keyPath, pfxPath string, enc *KeyEncryption) (*KeyPair, string, error) {
	existingKey, err := existingPrivateFile(keyPath)
	if err != nil {
		return nil, "", err
	}
	hasCert, hasKey := fileExists(certPath), existingKey != ""
	switch {
	case !hasCert && !hasKey:
		return nil, keyPath, nil
	case !hasKey:
		return nil, "", fmt.Errorf("%w: %s exists but its key %s does not; delete %s to regenerate %q", ErrExistingFiles, certPath, keyPath, certPath, spec.CommonName)
	case !hasCert:
		return nil, "", fmt.Errorf("%w: %s exists but its certificate %s does not; delete %s to regenerate %q", ErrExistingFiles, existingKey, certPath, existingKey, spec.CommonName)
	}
	keyPath = existingKey

	kp, err := enc.ReadKeyPairFromFile(certPath, keyPath)
	if err != nil {
		return nil, "", fmt.Errorf("%w: %w", ErrExistingFiles, err)
	}
	kp, err = checkReusedKeyPair(spec, args, kp, certPath, keyPath, pfxPath, enc)
	return kp, keyPath, err
}

// checkReusedKeyPair returns kp if it still fits spec and its place in the
// hierarchy described by args.
func checkReusedKeyPair(spec *CertificateSpec, args *Args, kp *KeyPair, certPath, keyPath, pfxPath string, enc *KeyEncryption) (*KeyPair, error) {
	cert, key, err := ReadKeyPair(kp.PublicCertificate, kp.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %s and %s: %v", ErrExistingFiles, certPath, keyPath, err)
	}
	problem := func(format string, a ...any) error {
		return fmt.Errorf("%w: %s %s; delete %s and %s to regenerate %q", ErrExistingFiles, certPath, fmt.Sprintf(format, a...), certPath, keyPath, spec.CommonName)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, problem("has a key of type %T that cannot sign", key)
	}
	if pub, ok := cert.PublicKey.(interface{ Equal(crypto.PublicKey) bool }); !ok || !pub.Equal(signer.Public()) {
		return nil, problem("does not match the key in %s", keyPath)
	}
	if cert.Subject.CommonName != spec.CommonName {
		return nil, problem("is for %q, not %q", cert.Subject.CommonName, spec.CommonName)
	}
	if cert.IsCA != spec.CertificateAuthority {
		return nil, problem("has CA %t but the spec has certificateAuthority %t", cert.IsCA, spec.CertificateAuthority)
	}
	if time.Now().After(cert.NotAfter) {
		return nil, problem("expired at %s", cert.NotAfter.Format(time.RFC3339))
	}

	var parent *x509.Certificate
	switch {
	case args.Issuer != nil:
		parent = args.Issuer.Certificate
	case args.ParentKeyPair != nil:
		parentCert, _, err := ReadKeyPair(args.ParentKeyPair.PublicCertificate, args.ParentKeyPair.PrivateKey)
		if err != nil {
			return nil, err
		}
		parent = parentCert
	}
	if parent == nil {
		// Self-signed. CheckSignatureFrom only accepts a CA as the parent, so
		// check the signature against the certificate's own key directly.
		if err := cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature); err != nil {
			return nil, problem("is not validly self-signed: %v", err)
		}
	} else if err := cert.CheckSignatureFrom(parent); err != nil {
		return nil, problem("is not signed by %q, which issues it in the spec, probably because that certificate was regenerated", parent.Subject.CommonName)
	}

	if !spec.CodeSigning {
		return kp, nil
	}
	target := args.Target
	if target == "" {
		target = windows10Target
	}
	profile, err := GetProfile(target)
	if err != nil || !profile.OutputPFX {
		return kp, err
	}
	existingPFX, err := existingPrivateFile(pfxPath)
	if err != nil {
		return nil, err
	}
	if existingPFX != "" {
		if kp.PFX, err = enc.ReadPrivateFile(existingPFX); err != nil {
			return nil, fmt.Errorf("%w: cannot read %s: %v", ErrExistingFiles, existingPFX, err)
		}
		return kp, nil
	}
	if kp.PFX, err = toPFX(cert, key, args.PFXPassword, profile.LegacyPFX); err != nil {
		return nil, fmt.Errorf("cannot rebuild the PFX for %q from %s: %w", spec.CommonName, keyPath, err)
	}
	return kp, nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
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
