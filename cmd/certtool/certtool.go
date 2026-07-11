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

// Package main is the entry point for certtool.
package main

import (
	"flag"
	"fmt"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/cloudfra/certtool/pkg/certtool"
	"go.uber.org/zap"
)

var (
	publicCertificate = flag.String("public-certificate", "app.cert", "X.509 public certificate file to generate.")
	privateKey        = flag.String("private-key", "app.key", "Private key file to generate.")

	ca = flag.Bool("ca", false, "Generates a root certificate. Use this to establish a chain of trust with derived certificates.")

	country            = flag.String("country", "US", "Country (C) field of the X.509 certificate subject (e.g. US, CA, GB).")
	organization       = flag.String("organization", "cloudfra", "Organization (O) field of the X.509 certificate subject.")
	organizationalUnit = flag.String("organizational-unit", "gows", "Organizational Unit (OU) field of the X.509 certificate subject.")
	locality           = flag.String("locality", "Seattle", "Locality (L) field of the X.509 certificate subject, typically the city name.")
	province           = flag.String("province", "WA", "Province or state (ST) field of the X.509 certificate subject.")

	hostnames = flag.String("hostnames", "", "Comma-separated list of hostnames and IP addresses to include as Subject Alternative Names (SANs).")
	keyType   = flag.String("key-type", "RSA-2048", "Key algorithm and length. Supported values: RSA-2048, RSA-4096, ECDSA-224, ECDSA-256, ECDSA-384, ECDSA-521. Default for --code-sign is the profile default.")

	parentPublicCertificate = flag.String("parent-public-certificate", "", "(optional) Parent public certificate. If set, the output certificate will trust the parent.")
	parentPrivateKey        = flag.String("parent-private-key", "", "(optional) Parent private key. Required if -parent-public-certificate is set, private key for the parent public certificate.")

	codeSigning = flag.Bool("code-sign", false, "Generates a code signing certificate for binary signing instead of a TLS certificate.")
	target      = flag.String("target", "", "Platform profile for --code-sign. Values: windows7 (win7/windows8/win8), windows10 (win10), windows11 (win11), linux. Default: windows10.")
	pfxOutput   = flag.String("pfx-output", "codesign.pfx", "Output path for the PKCS#12 (.pfx) file. Used with --code-sign for Windows targets.")
	pfxPassword = flag.String("pfx-password", "", "Password for the PKCS#12 (.pfx) file. Empty means no password.")
)

const (
	algorithmRSA          = "RSA"
	algorithmECDSA        = "ECDSA"
	defaultCodeSignTarget = "windows10"
)

func main() {
	os.Exit(certtoolMain())
}

// certtoolMain runs the tool and returns the process exit code.
func certtoolMain() int {
	flag.Parse()

	if *target != "" && !*codeSigning {
		zap.S().Warn("--target is set but --code-sign is not; --target will be ignored")
	}

	args, err := argsFromFlags()
	if err != nil {
		zap.S().Error(err)
		return 1
	}

	if err := generateAndWriteKeyPair(args); err != nil {
		zap.S().Error(err)
		return 1
	}

	return 0
}

func generateAndWriteKeyPair(args *certtool.Args) error {
	kp, err := certtool.GenerateKeyPair(args)
	if err != nil {
		return err
	}
	if len(kp.PFX) > 0 {
		return certtool.WritePFX(kp, *pfxOutput)
	}
	return certtool.WriteKeyPair(kp, *publicCertificate, *privateKey)
}

func argsFromFlags() (*certtool.Args, error) {
	var parent *certtool.KeyPair

	// Detect if --key-type was explicitly set by the user (not just the default value).
	// flag.Visit only visits flags explicitly set via flag.Parse or flag.Set.
	var keyTypeExplicitlySet bool
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "key-type" {
			keyTypeExplicitlySet = true
		}
	})

	var kt *certtool.KeyType
	if keyTypeExplicitlySet || !*codeSigning {
		algorithm, keyLength, err := StringToKeyType(*keyType)
		if err != nil {
			return nil, err
		}
		kt = &certtool.KeyType{Algorithm: algorithm, KeyLength: keyLength}

		// Warn if the user explicitly chose ECDSA for a Windows 7 target.
		if *codeSigning && strings.ToUpper(algorithm) == algorithmECDSA {
			effectiveTarget := *target
			if effectiveTarget == "" {
				effectiveTarget = defaultCodeSignTarget
			}
			if profile, profErr := certtool.GetProfile(effectiveTarget); profErr == nil && profile.LegacyPFX {
				zap.S().Warn("ECDSA code signing certs are not supported by Windows 7 signtool.exe; proceeding with user-specified key type")
			}
		}
	}
	// If kt is nil and codeSigning is true, fillDefaults resolves the key type from the profile.

	var err error
	if *parentPublicCertificate != "" {
		parent, err = certtool.ReadKeyPairFromFile(*parentPublicCertificate, *parentPrivateKey)
		if err != nil {
			return nil, err
		}
	}

	return &certtool.Args{
		CA:                 *ca,
		Country:            *country,
		Organization:       *organization,
		OrganizationalUnit: *organizationalUnit,
		Locality:           *locality,
		Province:           *province,
		Hostnames:          ExpandHostnames(*hostnames),
		KeyType:            kt,
		ParentKeyPair:      parent,
		CodeSigning:        *codeSigning,
		Target:             *target,
		PFXPassword:        *pfxPassword,
	}, nil
}

func StringToKeyType(keyType string) (string, int, error) {
	if keyType == "" {
		return algorithmRSA, 2048, nil
	}
	switch parseKeyTypeKeyName(keyType) {
	case algorithmRSA:
		return parseKeyTypeName(keyType, 2048, []int{2048, 4096})
	case algorithmECDSA:
		return parseKeyTypeName(keyType, 521, []int{224, 256, 384, 521})
	}
	return "", 0, fmt.Errorf("'%s' is not a valid key type", keyType)
}

func parseKeyTypeKeyName(keyTypeName string) string {
	parts := strings.Split(strings.ToUpper(keyTypeName), "-")
	if len(parts) > 0 {
		return parts[0]
	}
	return algorithmRSA
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

func ExpandHostnames(hostnameCsv string) []string {
	return expandHostnames(strings.Split(hostnameCsv, ","))
}

func expandHostnames(hostnames []string) []string {
	unique := map[string]any{}

	for _, hn := range hostnames {
		if hn != "" {
			unique[hn] = nil
		}
	}

	all := make([]string, 0, len(unique))
	for hn := range unique {
		all = append(all, hn)
	}
	sort.Strings(all)
	return all
}
