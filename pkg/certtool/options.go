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
	"log/slog"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Options is the complete configuration of one certtool run. Each field
// corresponds to a command-line flag of the same name, and the fields that
// take a list or a key type use the same syntax as the flag, so a front end
// only has to copy what the user typed. Start from DefaultOptions and change
// what you need, then pass the result to Run.
//
// Error messages and warnings refer to the equivalent command-line flag.
type Options struct {
	// PublicCertificate is the file the X.509 public certificate is written to
	// (--public-certificate).
	PublicCertificate string
	// PrivateKey is the file the private key is written to (--private-key).
	PrivateKey string

	// CA generates a root certificate that can sign others (--ca).
	CA bool

	// CommonName is the subject common name (--common-name). Defaults to
	// Organization when empty.
	CommonName string
	// Country is the subject country (--country), e.g. US.
	Country string
	// Organization is the subject organization (--organization).
	Organization string
	// OrganizationalUnit is the subject organizational unit
	// (--organizational-unit).
	OrganizationalUnit string
	// Locality is the subject locality (--locality).
	Locality string
	// Province is the subject state or province (--province).
	Province string

	// Validity is how long the certificate is valid for (--validity). It must
	// be positive.
	Validity time.Duration
	// Hostnames is a comma-separated list of hostnames and IP addresses added
	// as Subject Alternative Names (--hostnames).
	Hostnames string
	// KeyType is the key algorithm and length, such as RSA-2048 or ECDSA-256
	// (--key-type). When empty a TLS certificate uses RSA-2048 and a code
	// signing certificate uses the default of its Target profile.
	KeyType string
	// Ports is a comma-separated list of ports applied to every hostname that
	// does not already have one (--ports).
	Ports string

	// ParentPublicCertificate and ParentPrivateKey are the files of the CA that
	// signs the certificate (--parent-public-certificate and
	// --parent-private-key). Leave both empty for a self-signed certificate.
	ParentPublicCertificate string
	ParentPrivateKey        string

	// CodeSigning generates a code signing certificate instead of a TLS
	// certificate (--code-sign).
	CodeSigning bool
	// Target is the platform profile for code signing (--target), such as
	// windows10 or linux.
	Target string
	// PFXOutput is where the PKCS#12 bundle of a Windows code signing
	// certificate is written (--pfx-output).
	PFXOutput string
	// PFXPassword protects the PKCS#12 bundle (--pfx-password). Empty means no
	// password.
	PFXPassword string

	// Spec is the path of a YAML file describing the certificates to generate
	// (--spec). It cannot be combined with Chain.
	Spec string
	// Chain generates a hierarchy from the number of certificates in each layer
	// (--chain), for example "3", "1,1" or "1,2,3". See ChainToSpec. It cannot
	// be combined with Spec.
	Chain string
	// NamePrefix is placed in front of the common name of every certificate
	// Chain generates (--name-prefix).
	NamePrefix string
	// OutputDir is where certificates generated from Spec or Chain are written
	// (--output-dir).
	OutputDir string
	// ExportSpec is a path to write the resolved certificate spec to as YAML
	// instead of generating certificates (--export-spec). It works with Spec,
	// Chain, or the single-certificate options.
	ExportSpec string
}

// DefaultOptions returns the options certtool uses when no flags are given.
func DefaultOptions() Options {
	return Options{
		PublicCertificate:  "app.cert",
		PrivateKey:         "app.key",
		Country:            "US",
		Organization:       "cloudfra",
		OrganizationalUnit: "gows",
		Locality:           "Seattle",
		Province:           "WA",
		Validity:           oneYear,
		PFXOutput:          "codesign.pfx",
		OutputDir:          ".",
	}
}

// args validates the single-certificate options and converts them to Args.
func (o *Options) args() (*Args, error) {
	// An empty key type means "not chosen": a code signing certificate then
	// takes the key type of its platform profile.
	var kt *KeyType
	if o.KeyType != "" || !o.CodeSigning {
		algorithm, keyLength, err := stringToKeyType(o.KeyType)
		if err != nil {
			return nil, err
		}
		kt = &KeyType{Algorithm: algorithm, KeyLength: keyLength}

		// Warn if the user explicitly chose ECDSA for a Windows 7 target.
		if o.CodeSigning && strings.ToUpper(algorithm) == ecdsaAlgorithm {
			effectiveTarget := o.Target
			if effectiveTarget == "" {
				effectiveTarget = windows10Target
			}
			if profile, err := GetProfile(effectiveTarget); err == nil && profile.LegacyPFX {
				slog.Warn("ECDSA code signing certs are not supported by Windows 7 signtool.exe; proceeding with user-specified key type")
			}
		}
	}

	var parent *KeyPair
	if o.ParentPublicCertificate != "" {
		var err error
		parent, err = ReadKeyPairFromFile(o.ParentPublicCertificate, o.ParentPrivateKey)
		if err != nil {
			return nil, err
		}
	}

	if o.Validity <= 0 {
		return nil, fmt.Errorf("--validity must be a positive duration, got %s", o.Validity)
	}

	portList, err := splitInts(o.Ports)
	if err != nil {
		return nil, err
	}
	return &Args{
		CA:                 o.CA,
		CommonName:         o.CommonName,
		Country:            o.Country,
		Organization:       o.Organization,
		OrganizationalUnit: o.OrganizationalUnit,
		Locality:           o.Locality,
		Province:           o.Province,
		Validity:           o.Validity,
		Hostnames:          splitStrings(o.Hostnames),
		Ports:              portList,
		KeyType:            kt,
		ParentKeyPair:      parent,
		CodeSigning:        o.CodeSigning,
		Target:             o.Target,
		PFXPassword:        o.PFXPassword,
	}, nil
}

// flagsToSpec expresses the single-certificate options as a one-entry spec.
func (o *Options) flagsToSpec() ([]CertificateSpec, error) {
	portList, err := splitInts(o.Ports)
	if err != nil {
		return nil, err
	}

	cn := o.CommonName
	if cn == "" {
		cn = o.Organization
	}

	// Record the key type the tool would use, so the spec generates the same
	// certificate as the options. Code signing keeps it empty because its
	// default comes from the target profile.
	kt := o.KeyType
	if kt == "" && !o.CodeSigning {
		kt = "RSA-2048"
	}

	return []CertificateSpec{{
		CommonName:           cn,
		CertificateAuthority: o.CA,
		CodeSigning:          o.CodeSigning,
		Target:               o.Target,
		PFXPassword:          o.PFXPassword,
		KeyType:              kt,
		Validity:             o.Validity.String(),
		Organization:         o.Organization,
		OrganizationalUnit:   o.OrganizationalUnit,
		Country:              o.Country,
		Locality:             o.Locality,
		Province:             o.Province,
		Hostnames:            splitStrings(o.Hostnames),
		Ports:                portList,
	}}, nil
}

// chainWidths parses the layer widths of a --chain value such as "1,2,3".
func chainWidths(chain string) ([]int, error) {
	parts := strings.Split(chain, ",")
	widths := make([]int, len(parts))
	for i, p := range parts {
		p = strings.TrimSpace(p)
		v, err := strconv.Atoi(p)
		if err != nil {
			return nil, fmt.Errorf("--chain value %q is not a valid integer", p)
		}
		widths[i] = v
	}
	return widths, nil
}

func stringToKeyType(keyType string) (string, int, error) {
	if keyType == "" {
		return rsaAlgorithm, 2048, nil
	}
	switch parseKeyTypeKeyName(keyType) {
	case rsaAlgorithm:
		return parseKeyTypeName(keyType, 2048, []int{2048, 4096})
	case ecdsaAlgorithm:
		return parseKeyTypeName(keyType, 521, []int{224, 256, 384, 521})
	}
	return "", 0, fmt.Errorf("'%s' is not a valid key type", keyType)
}

func parseKeyTypeKeyName(keyTypeName string) string {
	parts := strings.Split(strings.ToUpper(keyTypeName), "-")
	if len(parts) > 0 {
		return parts[0]
	}
	return rsaAlgorithm
}

func parseKeyTypeName(keyTypeName string, defaultLength int, validValues []int) (string, int, error) {
	parts := strings.Split(strings.ToUpper(keyTypeName), "-")
	if len(parts) > 2 {
		return "", 0, fmt.Errorf("key type '%s' is not valid", keyTypeName)
	}
	if len(parts) == 0 {
		return "", 0, fmt.Errorf("key type does not have a name")
	}

	algorithm := parts[0]
	keyLength := ""
	if len(parts) == 2 {
		keyLength = parts[1]
	}

	if keyLength == "" {
		return algorithm, defaultLength, nil
	}
	length, err := strconv.Atoi(parts[1])
	if err != nil {
		return "", 0, fmt.Errorf("key type '%s' does not have a valid %s key length", keyTypeName, algorithm)
	}
	if slices.Contains(validValues, length) {
		return algorithm, length, nil
	}

	return "", 0, fmt.Errorf("key type '%s' does not have a valid %s key length", keyTypeName, algorithm)
}

func splitStrings(csv string) []string {
	if csv == "" {
		return nil
	}
	parts := strings.Split(csv, ",")
	for i, p := range parts {
		parts[i] = strings.TrimSpace(p)
	}
	return parts
}

func splitInts(csv string) ([]int, error) {
	if csv == "" {
		return nil, nil
	}
	vals := splitStrings(csv)
	result := make([]int, len(vals))
	for i, v := range vals {
		iv, err := strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("cannot convert %q to an integer, %w", v, err)
		}
		if iv < 1 || iv > 65535 {
			return nil, fmt.Errorf("port %d is not valid, must be between 1 and 65535", iv)
		}
		result[i] = iv
	}
	return result, nil
}
