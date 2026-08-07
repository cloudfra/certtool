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

package main

import (
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cloudfra/certtool/pkg/certtool"
)

func TestCerttoolMainVersion(t *testing.T) {
	origVersion := *version
	*version = true
	t.Cleanup(func() { *version = origVersion })

	if got := certtoolMain(); got != 0 {
		t.Errorf("certtoolMain() = %d, want 0 when --version is set", got)
	}
}

func TestArgsFromFlags(t *testing.T) {
	args, err := argsFromFlags()
	if err != nil {
		t.Fatalf("got error, %s", err)
	}
	if args.CA {
		t.Errorf("args.CA = %t, want false", args.CA)
	}
}

func TestCerttoolMain(t *testing.T) {
	dir := t.TempDir()
	origPublicCertificate, origPrivateKey := *publicCertificate, *privateKey
	*publicCertificate = filepath.Join(dir, "app.cert")
	*privateKey = filepath.Join(dir, "app.key")
	t.Cleanup(func() {
		*publicCertificate, *privateKey = origPublicCertificate, origPrivateKey
	})

	if got := certtoolMain(); got != 0 {
		t.Errorf("certtoolMain() = %d, want 0", got)
	}
	if _, err := os.Stat(*publicCertificate); err != nil {
		t.Errorf("expected public certificate to be written: %s", err)
	}
	if _, err := os.Stat(*privateKey); err != nil {
		t.Errorf("expected private key to be written: %s", err)
	}
}

func TestCerttoolMainInvalidKeyType(t *testing.T) {
	origKeyType := *keyType
	*keyType = "not-a-real-key-type"
	t.Cleanup(func() { *keyType = origKeyType })

	if got := certtoolMain(); got != 1 {
		t.Errorf("certtoolMain() = %d, want 1 for an invalid --key-type", got)
	}
}

func TestCerttoolMainWriteFailure(t *testing.T) {
	origPublicCertificate := *publicCertificate
	*publicCertificate = filepath.Join(t.TempDir(), "does-not-exist", "app.cert")
	t.Cleanup(func() { *publicCertificate = origPublicCertificate })

	if got := certtoolMain(); got != 1 {
		t.Errorf("certtoolMain() = %d, want 1 when the output directory does not exist", got)
	}
}

func TestCerttoolMainTargetWithoutCodeSign(t *testing.T) {
	dir := t.TempDir()
	origPublicCertificate, origPrivateKey, origTarget := *publicCertificate, *privateKey, *target
	*publicCertificate = filepath.Join(dir, "app.cert")
	*privateKey = filepath.Join(dir, "app.key")
	*target = defaultCodeSignTarget
	t.Cleanup(func() {
		*publicCertificate, *privateKey, *target = origPublicCertificate, origPrivateKey, origTarget
	})

	if got := certtoolMain(); got != 0 {
		t.Errorf("certtoolMain() = %d, want 0; --target should only warn, not fail, when --code-sign is unset", got)
	}
}

func TestGenerateAndWriteKeyPairError(t *testing.T) {
	err := generateAndWriteKeyPair(&certtool.Args{CodeSigning: true, Target: "not-a-real-target"})
	if err == nil {
		t.Fatal("generateAndWriteKeyPair() = nil, want error for an invalid --target")
	}
}

func TestGenerateAndWriteKeyPairPFX(t *testing.T) {
	origPfxOutput := *pfxOutput
	*pfxOutput = filepath.Join(t.TempDir(), "codesign.pfx")
	t.Cleanup(func() { *pfxOutput = origPfxOutput })

	if err := generateAndWriteKeyPair(&certtool.Args{CodeSigning: true, Target: defaultCodeSignTarget}); err != nil {
		t.Fatalf("generateAndWriteKeyPair() got error, %s", err)
	}
	if _, err := os.Stat(*pfxOutput); err != nil {
		t.Errorf("expected PFX file to be written: %s", err)
	}
}

func TestArgsFromFlagsExplicitECDSAOnWindows7(t *testing.T) {
	origCodeSigning, origKeyType, origTarget := *codeSigning, *keyType, *target
	t.Cleanup(func() {
		*codeSigning, *keyType, *target = origCodeSigning, origKeyType, origTarget
	})

	if err := flag.Set("code-sign", "true"); err != nil {
		t.Fatalf("flag.Set(code-sign) got error, %s", err)
	}
	if err := flag.Set("key-type", "ECDSA-256"); err != nil {
		t.Fatalf("flag.Set(key-type) got error, %s", err)
	}
	*target = "windows7"

	args, err := argsFromFlags()
	if err != nil {
		t.Fatalf("got error, %s", err)
	}
	if args.KeyType == nil || args.KeyType.Algorithm != algorithmECDSA || args.KeyType.KeyLength != 256 {
		t.Errorf("args.KeyType = %+v, want ECDSA-256", args.KeyType)
	}
}

func TestArgsFromFlagsExplicitECDSANoTarget(t *testing.T) {
	origCodeSigning, origKeyType, origTarget := *codeSigning, *keyType, *target
	t.Cleanup(func() {
		*codeSigning, *keyType, *target = origCodeSigning, origKeyType, origTarget
	})

	if err := flag.Set("code-sign", "true"); err != nil {
		t.Fatalf("flag.Set(code-sign) got error, %s", err)
	}
	if err := flag.Set("key-type", "ECDSA-256"); err != nil {
		t.Fatalf("flag.Set(key-type) got error, %s", err)
	}
	*target = ""

	// No --target set; the ECDSA/Windows-7 warning check should default the
	// effective target to windows10 rather than warn.
	args, err := argsFromFlags()
	if err != nil {
		t.Fatalf("got error, %s", err)
	}
	if args.KeyType == nil || args.KeyType.Algorithm != algorithmECDSA || args.KeyType.KeyLength != 256 {
		t.Errorf("args.KeyType = %+v, want ECDSA-256", args.KeyType)
	}
}

func TestArgsFromFlagsParentCertificateError(t *testing.T) {
	origParentPublicCertificate, origParentPrivateKey := *parentPublicCertificate, *parentPrivateKey
	*parentPublicCertificate = filepath.Join(t.TempDir(), "missing.cert")
	*parentPrivateKey = filepath.Join(t.TempDir(), "missing.key")
	t.Cleanup(func() {
		*parentPublicCertificate, *parentPrivateKey = origParentPublicCertificate, origParentPrivateKey
	})

	if _, err := argsFromFlags(); err == nil {
		t.Fatal("argsFromFlags() = nil, want error for a missing --parent-public-certificate file")
	}
}

func TestStringToKeyType(t *testing.T) {
	testCases := []struct {
		input         string
		wantAlgorithm string
		wantKeyLength int
	}{
		{input: "", wantAlgorithm: algorithmRSA, wantKeyLength: 2048},
		{input: algorithmRSA, wantAlgorithm: algorithmRSA, wantKeyLength: 2048},
		{input: "RSA-2048", wantAlgorithm: algorithmRSA, wantKeyLength: 2048},
		{input: "rsa-4096", wantAlgorithm: algorithmRSA, wantKeyLength: 4096},
		{input: "ecdsa-384", wantAlgorithm: algorithmECDSA, wantKeyLength: 384},
		{input: "ECDSA-521", wantAlgorithm: algorithmECDSA, wantKeyLength: 521},
		{input: algorithmECDSA, wantAlgorithm: algorithmECDSA, wantKeyLength: 521},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.input, func(t *testing.T) {
			t.Parallel()
			gotAlgorithm, gotKeyLength, err := stringToKeyType(tc.input)
			if err != nil {
				t.Fatalf("got error, %s", err)
			}
			if tc.wantAlgorithm != gotAlgorithm {
				t.Errorf("algorithm want: %v, got: %v", tc.wantAlgorithm, gotAlgorithm)
			}
			if tc.wantKeyLength != gotKeyLength {
				t.Errorf("keyLength want: %v, got: %v", tc.wantKeyLength, gotKeyLength)
			}
		})
	}
}

func TestSplitStrings(t *testing.T) {
	testCases := []struct {
		input string
		want  []string
	}{
		{input: "a,b,c", want: []string{"a", "b", "c"}},
		{input: "single", want: []string{"single"}},
		{input: "", want: nil},
		{input: "a,,b", want: []string{"a", "", "b"}},
		{input: "x,y", want: []string{"x", "y"}},
		{input: "a, b , c", want: []string{"a", "b", "c"}},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.input, func(t *testing.T) {
			t.Parallel()
			got := splitStrings(tc.input)
			if len(got) != len(tc.want) {
				t.Fatalf("splitStrings(%q) returned %d elements, want %d", tc.input, len(got), len(tc.want))
			}
			for i := range tc.want {
				if got[i] != tc.want[i] {
					t.Errorf("splitStrings(%q)[%d] = %q, want %q", tc.input, i, got[i], tc.want[i])
				}
			}
		})
	}
}

func TestSplitInts(t *testing.T) {
	testCases := []struct {
		input   string
		want    []int
		wantErr bool
	}{
		{input: "", want: nil},
		{input: "1,2,3", want: []int{1, 2, 3}},
		{input: "42", want: []int{42}},
		{input: "abc", wantErr: true},
		{input: "1,two,3", wantErr: true},
		{input: "1,,3", wantErr: true},
		{input: "0", wantErr: true},
		{input: "-1", wantErr: true},
		{input: "443,-1", wantErr: true},
		{input: "99999", wantErr: true},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.input, func(t *testing.T) {
			t.Parallel()
			got, err := splitInts(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("splitInts(%q) = nil error, want error", tc.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("splitInts(%q) got error: %s", tc.input, err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("splitInts(%q) returned %d elements, want %d", tc.input, len(got), len(tc.want))
			}
			for i := range tc.want {
				if got[i] != tc.want[i] {
					t.Errorf("splitInts(%q)[%d] = %d, want %d", tc.input, i, got[i], tc.want[i])
				}
			}
		})
	}
}

func TestArgsFromFlagsValidity(t *testing.T) {
	origValidity := *validity
	*validity = 48 * time.Hour
	t.Cleanup(func() { *validity = origValidity })

	args, err := argsFromFlags()
	if err != nil {
		t.Fatalf("got error, %s", err)
	}
	if args.Validity != 48*time.Hour {
		t.Errorf("args.Validity = %v, want 48h", args.Validity)
	}
}

func TestArgsFromFlagsValidityDefault(t *testing.T) {
	args, err := argsFromFlags()
	if err != nil {
		t.Fatalf("got error, %s", err)
	}
	if args.Validity != time.Hour*24*365 {
		t.Errorf("args.Validity = %v, want 8760h (1 year)", args.Validity)
	}
}

func TestArgsFromFlagsCommonName(t *testing.T) {
	origCommonName := *commonName
	*commonName = "my-service.example.com"
	t.Cleanup(func() { *commonName = origCommonName })

	args, err := argsFromFlags()
	if err != nil {
		t.Fatalf("got error, %s", err)
	}
	if args.CommonName != "my-service.example.com" {
		t.Errorf("args.CommonName = %q, want %q", args.CommonName, "my-service.example.com")
	}
}

func TestArgsFromFlagsNegativeValidity(t *testing.T) {
	origValidity := *validity
	*validity = -24 * time.Hour
	t.Cleanup(func() { *validity = origValidity })

	if _, err := argsFromFlags(); err == nil {
		t.Fatal("argsFromFlags() = nil, want error for negative --validity")
	}
}

func TestArgsFromFlagsInvalidPorts(t *testing.T) {
	origPorts := *ports
	*ports = "abc"
	t.Cleanup(func() { *ports = origPorts })

	if _, err := argsFromFlags(); err == nil {
		t.Fatal("argsFromFlags() = nil, want error for invalid --ports")
	}
}

func TestArgsFromFlagsCommonNameDefault(t *testing.T) {
	args, err := argsFromFlags()
	if err != nil {
		t.Fatalf("got error, %s", err)
	}
	if args.CommonName != "" {
		t.Errorf("args.CommonName = %q, want empty (defaults to organization in fillDefaults)", args.CommonName)
	}
}

func TestCerttoolMainSpec(t *testing.T) {
	dir := t.TempDir()
	specFile := filepath.Join(dir, "test.yaml")
	if err := os.WriteFile(specFile, []byte(`
- commonName: "Test Root CA"
  certificateAuthority: true
  keyType: "RSA-2048"
  validity: "8760h"
  children:
    - commonName: "leaf.example.com"
      keyType: "RSA-2048"
      validity: "8760h"
      hostnames:
        - leaf.example.com
`), 0o600); err != nil {
		t.Fatal(err)
	}

	origSpec, origOutputDir := *spec, *outputDir
	*spec = specFile
	*outputDir = dir
	t.Cleanup(func() { *spec, *outputDir = origSpec, origOutputDir })

	if got := certtoolMain(); got != 0 {
		t.Errorf("certtoolMain() = %d, want 0", got)
	}
	if _, err := os.Stat(filepath.Join(dir, "test-root-ca.cert")); err != nil {
		t.Errorf("expected root cert: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "test-root-ca-leaf-example-com.cert")); err != nil {
		t.Errorf("expected leaf cert: %v", err)
	}
}

func TestCerttoolMainSpecMissing(t *testing.T) {
	origSpec := *spec
	*spec = filepath.Join(t.TempDir(), "does-not-exist.yaml")
	t.Cleanup(func() { *spec = origSpec })

	if got := certtoolMain(); got != 1 {
		t.Errorf("certtoolMain() = %d, want 1 for missing spec file", got)
	}
}

func TestValidateModeFlags(t *testing.T) {
	t.Run("no modes", func(t *testing.T) {
		origChain, origSpec := *chain, *spec
		*chain = ""
		*spec = ""
		t.Cleanup(func() { *chain, *spec = origChain, origSpec })

		if err := validateModeFlags(); err != nil {
			t.Errorf("validateModeFlags() err = %v, want nil", err)
		}
	})

	t.Run("chain and spec", func(t *testing.T) {
		origChain, origSpec := *chain, *spec
		*chain = "2"
		*spec = "file.yaml"
		t.Cleanup(func() { *chain, *spec = origChain, origSpec })

		if err := validateModeFlags(); err == nil {
			t.Error("validateModeFlags() = nil, want error for mutually exclusive flags")
		}
	})
}

func TestCerttoolMainChain(t *testing.T) {
	dir := t.TempDir()
	origChain, origOutputDir := *chain, *outputDir
	*chain = "2"
	*outputDir = dir
	t.Cleanup(func() { *chain, *outputDir = origChain, origOutputDir })

	if got := certtoolMain(); got != 0 {
		t.Errorf("certtoolMain() = %d, want 0 for --chain 2", got)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir() err = %v", err)
	}
	if len(entries) < 4 {
		t.Errorf("expected at least 4 files (2 certs + 2 keys), got %d", len(entries))
	}
}

func TestCerttoolMainChainThreeTier(t *testing.T) {
	dir := t.TempDir()
	origChain, origOutputDir := *chain, *outputDir
	*chain = "3"
	*outputDir = dir
	t.Cleanup(func() { *chain, *outputDir = origChain, origOutputDir })

	if got := certtoolMain(); got != 0 {
		t.Errorf("certtoolMain() = %d, want 0 for --chain 3", got)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir() err = %v", err)
	}
	if len(entries) != 6 {
		t.Errorf("expected 6 files (3 certs + 3 keys), got %d", len(entries))
	}
}

func TestCerttoolMainChainBreadth(t *testing.T) {
	dir := t.TempDir()
	origChain, origOutputDir := *chain, *outputDir
	*chain = "1,2,3"
	*outputDir = dir
	t.Cleanup(func() { *chain, *outputDir = origChain, origOutputDir })

	if got := certtoolMain(); got != 0 {
		t.Errorf("certtoolMain() = %d, want 0 for --chain 1,2,3", got)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir() err = %v", err)
	}
	wantFiles := (1 + 2 + 2*3) * 2
	if len(entries) != wantFiles {
		t.Errorf("expected %d files, got %d", wantFiles, len(entries))
	}
}

func TestCerttoolMainChainInvalid(t *testing.T) {
	origChain := *chain
	*chain = "1"
	t.Cleanup(func() { *chain = origChain })

	if got := certtoolMain(); got != 1 {
		t.Errorf("certtoolMain() = %d, want 1 for --chain 1", got)
	}
}

func TestCerttoolMainExportSpec(t *testing.T) {
	dir := t.TempDir()
	outFile := filepath.Join(dir, "exported.yaml")

	origExportSpec, origChain, origOutputDir := *exportSpec, *chain, *outputDir
	*exportSpec = outFile
	*chain = "2"
	*outputDir = dir
	t.Cleanup(func() { *exportSpec, *chain, *outputDir = origExportSpec, origChain, origOutputDir })

	if got := certtoolMain(); got != 0 {
		t.Errorf("certtoolMain() = %d, want 0", got)
	}
	if _, err := os.Stat(outFile); err != nil {
		t.Errorf("expected spec file to be written: %v", err)
	}
}

func TestCerttoolMainExportSpecFromFlags(t *testing.T) {
	dir := t.TempDir()
	outFile := filepath.Join(dir, "flags.yaml")

	origExportSpec := *exportSpec
	*exportSpec = outFile
	t.Cleanup(func() { *exportSpec = origExportSpec })

	if got := certtoolMain(); got != 0 {
		t.Errorf("certtoolMain() = %d, want 0", got)
	}
	if _, err := os.Stat(outFile); err != nil {
		t.Errorf("expected spec file to be written: %v", err)
	}

	data, err := os.ReadFile(filepath.Clean(outFile))
	if err != nil {
		t.Fatalf("ReadFile() err = %v", err)
	}
	if len(data) == 0 {
		t.Error("exported spec file is empty")
	}
}

func TestCerttoolMainSpecWithExportSpec(t *testing.T) {
	dir := t.TempDir()
	specFile := filepath.Join(dir, "input.yaml")
	outFile := filepath.Join(dir, "output.yaml")
	if err := os.WriteFile(specFile, []byte(`
- commonName: "Test Root CA"
  certificateAuthority: true
  keyType: "RSA-2048"
  children:
    - commonName: "leaf.example.com"
      keyType: "RSA-2048"
`), 0o600); err != nil {
		t.Fatal(err)
	}

	origSpec, origExportSpec := *spec, *exportSpec
	*spec = specFile
	*exportSpec = outFile
	t.Cleanup(func() { *spec, *exportSpec = origSpec, origExportSpec })

	if got := certtoolMain(); got != 0 {
		t.Errorf("certtoolMain() = %d, want 0", got)
	}
	if _, err := os.Stat(outFile); err != nil {
		t.Errorf("expected output spec file: %v", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir() err = %v", err)
	}
	certCount := 0
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".cert" {
			certCount++
		}
	}
	if certCount != 0 {
		t.Errorf("expected no .cert files when --export-spec is set, got %d", certCount)
	}
}

func TestStringToKeyTypeErrors(t *testing.T) {
	testCases := []string{
		"bogus",          // unknown key type name
		"RSA-2048-EXTRA", // too many segments
		"RSA-abc",        // key length is not a number
		"RSA-9999",       // key length not a supported RSA length
		"ECDSA-9999",     // key length not a supported ECDSA length
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc, func(t *testing.T) {
			t.Parallel()
			if _, _, err := stringToKeyType(tc); err == nil {
				t.Errorf("stringToKeyType(%q) = nil error, want error", tc)
			}
		})
	}
}
