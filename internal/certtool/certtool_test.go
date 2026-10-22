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
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	certlib "github.com/cloudfra/certtool/pkg/certtool"
)

// testArgs returns the default options with every output in a new temporary
// directory, which is also the output directory.
func testArgs(t *testing.T) Args {
	t.Helper()

	dir := t.TempDir()
	args := DefaultArgs()
	args.PublicCertificate = filepath.Join(dir, "app.crt")
	args.PrivateKey = filepath.Join(dir, "app.key")
	args.PFXOutput = filepath.Join(dir, "codesign.pfx")
	args.OutputDir = dir
	return args
}

func writeSpec(t *testing.T, dir, name, content string) string {
	t.Helper()

	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func countFiles(t *testing.T, dir, pattern string) int {
	t.Helper()

	matches, err := filepath.Glob(filepath.Join(dir, pattern))
	if err != nil {
		t.Fatal(err)
	}
	return len(matches)
}

func TestRunVersion(t *testing.T) {
	args := testArgs(t)
	args.Version = true
	if err := Run(args); err != nil {
		t.Errorf("Run() err = %v, want nil when --version is set", err)
	}
	assertNoFiles(t, args.OutputDir)
}

func TestRun(t *testing.T) {
	args := testArgs(t)
	if err := Run(args); err != nil {
		t.Fatalf("Run() err = %v", err)
	}
	for _, f := range []string{args.PublicCertificate, args.PrivateKey} {
		if _, err := os.Stat(f); err != nil {
			t.Errorf("expected %s to be written: %s", f, err)
		}
	}
}

func TestRunErrors(t *testing.T) {
	testCases := []struct {
		name string
		set  func(t *testing.T, a *Args)
		want string
	}{
		{
			name: "invalid key type",
			set:  func(_ *testing.T, a *Args) { a.KeyType = "not-a-real-key-type" },
			want: "--key-type 'not-a-real-key-type' is not a valid key type",
		},
		{
			name: "invalid hostname",
			set:  func(_ *testing.T, a *Args) { a.Hostnames = "api.example.com,*.com" },
			want: `--hostnames: hostname "*.com" is not a valid DNS name or IP address`,
		},
		{
			name: "invalid hostname exported",
			set: func(t *testing.T, a *Args) {
				a.Hostnames, a.ExportSpec = "a b", filepath.Join(t.TempDir(), "out.yaml")
			},
			want: `--hostnames: hostname "a b"`,
		},
		{
			name: "invalid hostname in spec",
			set: func(t *testing.T, a *Args) {
				a.Spec = writeSpec(t, t.TempDir(), "certs.yaml", "- commonName: x\n  hostnames: [\"*\"]\n")
			},
			want: `spec "x": hostname "*" is not a valid DNS name`,
		},
		{
			name: "write failure",
			set: func(t *testing.T, a *Args) {
				a.PublicCertificate = filepath.Join(t.TempDir(), "does-not-exist", "app.crt")
			},
		},
		{
			name: "invalid target",
			set:  func(_ *testing.T, a *Args) { a.CodeSigning, a.Target = true, "not-a-real-target" },
		},
		{
			name: "missing spec",
			set:  func(t *testing.T, a *Args) { a.Spec = filepath.Join(t.TempDir(), "does-not-exist.yaml") },
		},
		{
			name: "chain of zero",
			set:  func(_ *testing.T, a *Args) { a.Chain = "0" },
		},
		{
			name: "chain not an integer",
			set:  func(_ *testing.T, a *Args) { a.Chain = "2,abc" },
			want: `--chain value "abc" is not a valid integer`,
		},
		{
			name: "chain and spec",
			set:  func(_ *testing.T, a *Args) { a.Chain, a.Spec = "2", "unused.yaml" },
			want: "--chain and --spec are mutually exclusive",
		},
		{
			name: "chain output directory cannot be created",
			set: func(t *testing.T, a *Args) {
				blocker := filepath.Join(t.TempDir(), "file")
				if err := os.WriteFile(blocker, nil, 0o600); err != nil {
					t.Fatal(err)
				}
				// A directory cannot be created beneath a regular file.
				a.Chain, a.OutputDir = "2", filepath.Join(blocker, "out")
			},
		},
		{
			name: "export spec write failure",
			set: func(t *testing.T, a *Args) {
				a.ExportSpec, a.Chain = filepath.Join(t.TempDir(), "missing", "out.yaml"), "2"
			},
		},
		{
			name: "parent certificate without key",
			set:  func(_ *testing.T, a *Args) { a.ParentPublicCertificate = "ca.crt" },
			want: "--parent-private-key is required with --parent-public-certificate",
		},
		{
			name: "parent key without certificate",
			set:  func(_ *testing.T, a *Args) { a.ParentPrivateKey = "ca.key" },
			want: "--parent-public-certificate is required with --parent-private-key",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			args := testArgs(t)
			tc.set(t, &args)
			err := Run(args)
			if err == nil {
				t.Fatal("Run() err = nil, want an error")
			}
			if tc.want != "" && !strings.Contains(err.Error(), tc.want) {
				t.Errorf("Run() err = %v, want it to contain %q", err, tc.want)
			}
		})
	}
}

func TestRunTargetWithoutCodeSign(t *testing.T) {
	args := testArgs(t)
	args.Target = defaultCodeSignTarget
	if err := Run(args); err != nil {
		t.Errorf("Run() err = %v, want nil; --target should only warn, not fail, when --code-sign is unset", err)
	}
}

func TestRunCodeSignPFX(t *testing.T) {
	args := testArgs(t)
	args.CodeSigning, args.Target = true, defaultCodeSignTarget
	if err := Run(args); err != nil {
		t.Fatalf("Run() err = %v", err)
	}
	if _, err := os.Stat(args.PFXOutput); err != nil {
		t.Errorf("expected PFX file to be written: %s", err)
	}
}

func TestRunParentCertificate(t *testing.T) {
	args := testArgs(t)
	args.CA = true
	if err := Run(args); err != nil {
		t.Fatalf("Run() for the CA err = %v", err)
	}

	child := testArgs(t)
	child.ParentPublicCertificate, child.ParentPrivateKey = args.PublicCertificate, args.PrivateKey
	if err := Run(child); err != nil {
		t.Fatalf("Run() for the child err = %v", err)
	}
}

func TestCertificateArgs(t *testing.T) {
	certArgs, err := certificateArgs(DefaultArgs())
	if err != nil {
		t.Fatalf("certificateArgs() err = %v", err)
	}
	if certArgs.CA {
		t.Errorf("CA = %t, want false", certArgs.CA)
	}
	if certArgs.Validity != 365*24*time.Hour {
		t.Errorf("Validity = %v, want 8760h (1 year)", certArgs.Validity)
	}
	if certArgs.CommonName != "" {
		t.Errorf("CommonName = %q, want empty (defaults to organization in fillDefaults)", certArgs.CommonName)
	}
	if certArgs.KeyType == nil || certArgs.KeyType.Algorithm != algorithmRSA || certArgs.KeyType.KeyLength != 2048 {
		t.Errorf("KeyType = %+v, want RSA-2048", certArgs.KeyType)
	}
}

func TestCertificateArgsFields(t *testing.T) {
	args := DefaultArgs()
	args.Validity = 48 * time.Hour
	args.CommonName = "my-service.example.com"
	args.Hostnames = "a.example.com, b.example.com"

	certArgs, err := certificateArgs(args)
	if err != nil {
		t.Fatalf("certificateArgs() err = %v", err)
	}
	if certArgs.Validity != 48*time.Hour {
		t.Errorf("Validity = %v, want 48h", certArgs.Validity)
	}
	if certArgs.CommonName != "my-service.example.com" {
		t.Errorf("CommonName = %q, want %q", certArgs.CommonName, "my-service.example.com")
	}
	if strings.Join(certArgs.Hostnames, " ") != "a.example.com b.example.com" {
		t.Errorf("Hostnames = %q, want a.example.com and b.example.com", certArgs.Hostnames)
	}
}

func TestCertificateArgsCodeSigningKeyType(t *testing.T) {
	for _, target := range []string{"windows7", ""} {
		t.Run("explicit ECDSA "+target, func(t *testing.T) {
			args := DefaultArgs()
			args.CodeSigning, args.KeyType, args.Target = true, "ECDSA-256", target

			certArgs, err := certificateArgs(args)
			if err != nil {
				t.Fatalf("certificateArgs() err = %v", err)
			}
			if certArgs.KeyType == nil || certArgs.KeyType.Algorithm != algorithmECDSA || certArgs.KeyType.KeyLength != 256 {
				t.Errorf("KeyType = %+v, want ECDSA-256", certArgs.KeyType)
			}
		})
	}

	t.Run("profile default", func(t *testing.T) {
		args := DefaultArgs()
		args.CodeSigning = true
		certArgs, err := certificateArgs(args)
		if err != nil {
			t.Fatalf("certificateArgs() err = %v", err)
		}
		if certArgs.KeyType != nil {
			t.Errorf("KeyType = %+v, want nil so the --target profile chooses it", certArgs.KeyType)
		}
	})
}

func TestCertificateArgsErrors(t *testing.T) {
	testCases := []struct {
		name string
		set  func(t *testing.T, a *Args)
	}{
		{"missing parent certificate", func(t *testing.T, a *Args) {
			a.ParentPublicCertificate = filepath.Join(t.TempDir(), "missing.crt")
			a.ParentPrivateKey = filepath.Join(t.TempDir(), "missing.key")
		}},
		{"negative validity", func(_ *testing.T, a *Args) { a.Validity = -24 * time.Hour }},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			args := DefaultArgs()
			tc.set(t, &args)
			if _, err := certificateArgs(args); err == nil {
				t.Error("certificateArgs() err = nil, want an error")
			}
		})
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

func TestStringToKeyTypeErrors(t *testing.T) {
	testCases := []string{
		"bogus",          // unknown key type name
		"RSA-2048-EXTRA", // too many segments
		"RSA-abc",        // key length is not a number
		"RSA-9999",       // key length not a supported RSA length
		"ECDSA-9999",     // key length not a supported ECDSA length
	}

	for _, tc := range testCases {
		t.Run(tc, func(t *testing.T) {
			t.Parallel()
			_, _, err := stringToKeyType(tc)
			if err == nil || !strings.Contains(err.Error(), "--key-type") {
				t.Errorf("stringToKeyType(%q) err = %v, want an error naming --key-type", tc, err)
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

func TestRunSpec(t *testing.T) {
	args := testArgs(t)
	args.Spec = writeSpec(t, args.OutputDir, "test.yaml", `
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
`)

	if err := Run(args); err != nil {
		t.Fatalf("Run() err = %v", err)
	}
	for _, f := range []string{"test-root-ca.crt", "test-root-ca-leaf-example-com.crt"} {
		if _, err := os.Stat(filepath.Join(args.OutputDir, f)); err != nil {
			t.Errorf("expected %s: %v", f, err)
		}
	}
}

func TestRunSpecCodeSigningPFX(t *testing.T) {
	args := testArgs(t)
	args.Spec = writeSpec(t, args.OutputDir, "codesign.yaml", `
- commonName: "Test Signer"
  codeSigning: true
  target: windows10
`)

	if err := Run(args); err != nil {
		t.Fatalf("Run() err = %v", err)
	}
	if got := countFiles(t, args.OutputDir, "*.pfx"); got != 1 {
		t.Errorf("wrote %d PFX files, want 1", got)
	}
}

func TestRunChain(t *testing.T) {
	testCases := []struct {
		chain     string
		wantCerts int
	}{
		{chain: "1,1", wantCerts: 2},
		{chain: "1,1,1", wantCerts: 3},
		{chain: "1,2,3", wantCerts: 1 + 2 + 2*3},
		{chain: "3", wantCerts: 3},
	}
	for _, tc := range testCases {
		t.Run(tc.chain, func(t *testing.T) {
			args := testArgs(t)
			args.Chain = tc.chain
			if err := Run(args); err != nil {
				t.Fatalf("Run() err = %v", err)
			}
			if got := countFiles(t, args.OutputDir, "*.crt"); got != tc.wantCerts {
				t.Errorf("wrote %d certificates, want %d", got, tc.wantCerts)
			}
			if got := countFiles(t, args.OutputDir, "*.key"); got != tc.wantCerts {
				t.Errorf("wrote %d keys, want %d", got, tc.wantCerts)
			}
		})
	}
}

func TestRunChainNamePrefix(t *testing.T) {
	args := testArgs(t)
	args.Chain, args.NamePrefix = "1,1", "prod"
	if err := Run(args); err != nil {
		t.Fatalf("Run() err = %v", err)
	}
	for _, f := range []string{"prod-cloudfra-root-ca.crt", "prod-cloudfra-root-ca-prod-cloudfra.crt"} {
		if _, err := os.Stat(filepath.Join(args.OutputDir, f)); err != nil {
			t.Errorf("expected the certificate to carry the prefix: %v", err)
		}
	}
}

func TestRunNamePrefixWithoutChain(t *testing.T) {
	args := testArgs(t)
	args.NamePrefix = "prod"
	if err := Run(args); err != nil {
		t.Errorf("Run() err = %v, want nil; --name-prefix should only warn, not fail, when --chain is unset", err)
	}
}

func TestRunExportSpec(t *testing.T) {
	args := testArgs(t)
	args.ExportSpec, args.Chain = filepath.Join(args.OutputDir, "exported.yaml"), "2"
	if err := Run(args); err != nil {
		t.Fatalf("Run() err = %v", err)
	}
	if _, err := os.Stat(args.ExportSpec); err != nil {
		t.Errorf("expected spec file to be written: %v", err)
	}
	if got := countFiles(t, args.OutputDir, "*.crt"); got != 0 {
		t.Errorf("wrote %d certificates with --export-spec, want none", got)
	}
}

func TestRunExportSpecFromFlags(t *testing.T) {
	args := testArgs(t)
	args.ExportSpec = filepath.Join(args.OutputDir, "flags.yaml")
	if err := Run(args); err != nil {
		t.Fatalf("Run() err = %v", err)
	}

	specs, err := certlib.ReadSpec(args.ExportSpec)
	if err != nil {
		t.Fatalf("ReadSpec() err = %v", err)
	}
	if len(specs) != 1 || specs[0].CommonName != "cloudfra" || specs[0].KeyType != "RSA-2048" {
		t.Errorf("exported %+v, want one RSA-2048 certificate named cloudfra", specs)
	}
}

// Code signing takes its key type from the --target profile, so an exported
// code signing spec must not pin RSA-2048.
func TestRunExportSpecCodeSigningKeyType(t *testing.T) {
	args := testArgs(t)
	args.ExportSpec, args.CodeSigning = filepath.Join(args.OutputDir, "codesign.yaml"), true
	if err := Run(args); err != nil {
		t.Fatalf("Run() err = %v", err)
	}

	specs, err := certlib.ReadSpec(args.ExportSpec)
	if err != nil {
		t.Fatalf("ReadSpec() err = %v", err)
	}
	if len(specs) != 1 || specs[0].KeyType != "" {
		t.Errorf("exported key type %q, want none so the --target profile chooses it", specs[0].KeyType)
	}
}

func TestRunSpecWithExportSpec(t *testing.T) {
	args := testArgs(t)
	args.Spec = writeSpec(t, args.OutputDir, "input.yaml", `
- commonName: "Test Root CA"
  certificateAuthority: true
  keyType: "RSA-2048"
  children:
    - commonName: "leaf.example.com"
      keyType: "RSA-2048"
`)
	args.ExportSpec = filepath.Join(args.OutputDir, "output.yaml")

	if err := Run(args); err != nil {
		t.Fatalf("Run() err = %v", err)
	}
	if _, err := os.Stat(args.ExportSpec); err != nil {
		t.Errorf("expected output spec file: %v", err)
	}
	if got := countFiles(t, args.OutputDir, "*.crt"); got != 0 {
		t.Errorf("wrote %d certificates with --export-spec, want none", got)
	}
}

// --spec and --chain reuse the files they already wrote unless --overwrite is
// given, so a hierarchy can be extended rather than reset.
func TestRunReusesExistingFiles(t *testing.T) {
	for name, set := range map[string]func(t *testing.T, a *Args){
		"spec": func(t *testing.T, a *Args) {
			a.Spec = writeSpec(t, t.TempDir(), "certs.yaml", "- commonName: Root\n  certificateAuthority: true\n  keyType: ECDSA-256\n  filename: root\n  children:\n    - commonName: api\n      keyType: ECDSA-256\n      filename: api\n")
		},
		"chain": func(_ *testing.T, a *Args) { a.Chain, a.KeyType = "1,1", "ECDSA-256" },
	} {
		t.Run(name, func(t *testing.T) {
			args := testArgs(t)
			set(t, &args)
			if err := Run(args); err != nil {
				t.Fatalf("Run() err = %v", err)
			}
			keys := func() string {
				var all strings.Builder
				matches, err := filepath.Glob(filepath.Join(args.OutputDir, "*.key"))
				if err != nil || len(matches) != 2 {
					t.Fatalf("found keys %v (err %v), want 2", matches, err)
				}
				for _, m := range matches {
					data, err := os.ReadFile(m) //nolint:gosec // m is a file the test created.
					if err != nil {
						t.Fatal(err)
					}
					all.Write(data)
				}
				return all.String()
			}
			first := keys()

			if err := Run(args); err != nil {
				t.Fatalf("Run() again err = %v", err)
			}
			if keys() != first {
				t.Error("running again replaced the keys, want them reused")
			}

			args.Overwrite = true
			if err := Run(args); err != nil {
				t.Fatalf("Run() with --overwrite err = %v", err)
			}
			if keys() == first {
				t.Error("--overwrite kept the keys, want them regenerated")
			}
		})
	}
}

func TestRunUnusableFilesSuggestOverwrite(t *testing.T) {
	args := testArgs(t)
	args.Spec = writeSpec(t, t.TempDir(), "certs.yaml", "- commonName: Leaf\n  keyType: ECDSA-256\n  filename: leaf\n")
	if err := Run(args); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(args.OutputDir, "leaf.key")); err != nil {
		t.Fatal(err)
	}
	err := Run(args)
	if !errors.Is(err, certlib.ErrExistingFiles) || !strings.Contains(err.Error(), "or pass --overwrite to regenerate every certificate") {
		t.Errorf("Run() err = %v, want ErrExistingFiles suggesting --overwrite", err)
	}
}

func TestValidateModesOverwrite(t *testing.T) {
	args := DefaultArgs()
	args.Overwrite = true
	if err := validateModes(args); err == nil || !strings.Contains(err.Error(), "--overwrite only applies to --spec and --chain") {
		t.Errorf("validateModes() err = %v, want an --overwrite misuse error", err)
	}
}
