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
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// captureLogs routes the default slog logger into a buffer for the test.
// Tests that use it must not run in parallel.
func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}

// testOptions returns the default options with every output redirected into a
// fresh temporary directory, which it also returns.
func testOptions(t *testing.T) (Options, string) {
	t.Helper()
	dir := t.TempDir()
	opts := DefaultOptions()
	opts.PublicCertificate = filepath.Join(dir, "app.cert")
	opts.PrivateKey = filepath.Join(dir, "app.key")
	opts.PFXOutput = filepath.Join(dir, "codesign.pfx")
	opts.OutputDir = dir
	return opts, dir
}

func writeSpecFile(t *testing.T, dir, name, content string) string {
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

func TestRun_SingleCertificate(t *testing.T) {
	opts, _ := testOptions(t)
	if err := Run(opts); err != nil {
		t.Fatalf("Run() err = %v", err)
	}
	if _, err := os.Stat(opts.PublicCertificate); err != nil {
		t.Errorf("expected public certificate to be written: %s", err)
	}
	if _, err := os.Stat(opts.PrivateKey); err != nil {
		t.Errorf("expected private key to be written: %s", err)
	}
}

func TestRun_SingleCertificateErrors(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Options, string)
	}{
		{"invalid key type", func(o *Options, _ string) { o.KeyType = "not-a-real-key-type" }},
		{"unwritable output", func(o *Options, dir string) {
			o.PublicCertificate = filepath.Join(dir, "does-not-exist", "app.cert")
		}},
		{"invalid code signing target", func(o *Options, _ string) {
			o.CodeSigning = true
			o.Target = "not-a-real-target"
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			opts, dir := testOptions(t)
			tc.mutate(&opts, dir)
			if err := Run(opts); err == nil {
				t.Error("Run() = nil error, want error")
			}
		})
	}
}

func TestRun_CodeSigningWritesPFX(t *testing.T) {
	opts, _ := testOptions(t)
	opts.CodeSigning = true
	opts.Target = "windows10"
	if err := Run(opts); err != nil {
		t.Fatalf("Run() err = %v", err)
	}
	if _, err := os.Stat(opts.PFXOutput); err != nil {
		t.Errorf("expected PFX file to be written: %s", err)
	}
}

func TestRun_WarnsAboutIgnoredFlags(t *testing.T) {
	logs := captureLogs(t)
	opts, _ := testOptions(t)
	opts.Target = "windows10" // --code-sign is not set
	opts.NamePrefix = "prod"  // --chain is not set

	if err := Run(opts); err != nil {
		t.Fatalf("Run() err = %v; ignored flags should only warn", err)
	}
	for _, want := range []string{"--target is set but --code-sign is not", "--name-prefix is set but --chain is not"} {
		if !strings.Contains(logs.String(), want) {
			t.Errorf("logs = %q, want a warning containing %q", logs.String(), want)
		}
	}
}

func TestRun_NoWarningsForValidFlags(t *testing.T) {
	logs := captureLogs(t)
	opts, _ := testOptions(t)
	if err := Run(opts); err != nil {
		t.Fatalf("Run() err = %v", err)
	}
	if logs.Len() != 0 {
		t.Errorf("logs = %q, want none", logs.String())
	}
}

func TestRun_ChainAndSpecConflict(t *testing.T) {
	opts, _ := testOptions(t)
	opts.Chain = "2"
	opts.Spec = "unused.yaml"
	if err := Run(opts); err == nil {
		t.Error("Run() = nil error, want an error for mutually exclusive --chain and --spec")
	}
}

func TestRun_Spec(t *testing.T) {
	logs := captureLogs(t)
	opts, dir := testOptions(t)
	opts.Spec = writeSpecFile(t, dir, "test.yaml", `
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

	if err := Run(opts); err != nil {
		t.Fatalf("Run() err = %v", err)
	}
	for _, name := range []string{"test-root-ca.cert", "test-root-ca-leaf-example-com.cert"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("expected %s: %v", name, err)
		}
	}
	if got := strings.Count(logs.String(), "generated certificate"); got != 2 {
		t.Errorf("logged %d generated certificates, want 2:\n%s", got, logs.String())
	}
}

func TestRun_SpecMissing(t *testing.T) {
	opts, dir := testOptions(t)
	opts.Spec = filepath.Join(dir, "does-not-exist.yaml")
	if err := Run(opts); err == nil {
		t.Error("Run() = nil error, want an error for a missing spec file")
	}
}

func TestRun_SpecCodeSigningLogsPFX(t *testing.T) {
	logs := captureLogs(t)
	opts, dir := testOptions(t)
	opts.Spec = writeSpecFile(t, dir, "codesign.yaml", `
- commonName: "Test Signer"
  codeSigning: true
  target: windows10
`)

	if err := Run(opts); err != nil {
		t.Fatalf("Run() err = %v", err)
	}
	if got := countFiles(t, dir, "*.pfx"); got != 1 {
		t.Errorf("got %d PFX files, want 1", got)
	}
	if !strings.Contains(logs.String(), "pfx=") {
		t.Errorf("logs = %q, want the PFX path to be logged", logs.String())
	}
}

func TestRun_Chain(t *testing.T) {
	tests := []struct {
		chain     string
		wantCerts int
	}{
		{"1,1", 2},
		{"1,1,1", 3},
		{"1,2,3", 1 + 2 + 2*3},
		{"3", 3},
	}
	for _, tc := range tests {
		t.Run(tc.chain, func(t *testing.T) {
			opts, dir := testOptions(t)
			opts.Chain = tc.chain
			if err := Run(opts); err != nil {
				t.Fatalf("Run() err = %v", err)
			}
			if got := countFiles(t, dir, "*.cert"); got != tc.wantCerts {
				t.Errorf("got %d certificates, want %d", got, tc.wantCerts)
			}
			if got := countFiles(t, dir, "*.key"); got != tc.wantCerts {
				t.Errorf("got %d keys, want %d", got, tc.wantCerts)
			}
		})
	}
}

func TestRun_ChainErrors(t *testing.T) {
	blocker := writeSpecFile(t, t.TempDir(), "file", "")
	tests := []struct {
		name   string
		mutate func(*Options)
	}{
		{"zero width", func(o *Options) { o.Chain = "0" }},
		{"not an integer", func(o *Options) { o.Chain = "2,abc" }},
		{"output directory cannot be created", func(o *Options) {
			o.Chain = "2"
			o.OutputDir = filepath.Join(blocker, "out") // a directory cannot be created beneath a regular file
		}},
		{"colliding common name", func(o *Options) {
			o.Chain = "1,1"
			o.CommonName = "cloudfra Root CA"
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			opts, _ := testOptions(t)
			tc.mutate(&opts)
			if err := Run(opts); err == nil {
				t.Error("Run() = nil error, want error")
			}
		})
	}
}

func TestRun_ChainNamePrefix(t *testing.T) {
	opts, dir := testOptions(t)
	opts.Chain = "1,1"
	opts.NamePrefix = "prod"
	if err := Run(opts); err != nil {
		t.Fatalf("Run() err = %v", err)
	}
	for _, name := range []string{"prod-cloudfra-root-ca.cert", "prod-cloudfra-root-ca-prod-cloudfra.cert"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("expected %s: %v", name, err)
		}
	}
}

func TestRun_ExportSpecFromChain(t *testing.T) {
	logs := captureLogs(t)
	opts, dir := testOptions(t)
	opts.Chain = "1,1"
	opts.ExportSpec = filepath.Join(dir, "exported.yaml")

	if err := Run(opts); err != nil {
		t.Fatalf("Run() err = %v", err)
	}
	specs, err := ReadSpec(opts.ExportSpec)
	if err != nil {
		t.Fatalf("exported spec is not readable: %v", err)
	}
	if len(specs) != 1 || len(specs[0].Children) != 1 {
		t.Errorf("exported specs = %+v, want a root with one leaf", specs)
	}
	if got := countFiles(t, dir, "*.cert"); got != 0 {
		t.Errorf("got %d certificates, want none when exporting a spec", got)
	}
	if !strings.Contains(logs.String(), "spec written") {
		t.Errorf("logs = %q, want the export to be logged", logs.String())
	}
}

func TestRun_ExportSpecFromFlags(t *testing.T) {
	opts, dir := testOptions(t)
	opts.ExportSpec = filepath.Join(dir, "flags.yaml")
	opts.Hostnames = "example.com"

	if err := Run(opts); err != nil {
		t.Fatalf("Run() err = %v", err)
	}
	specs, err := ReadSpec(opts.ExportSpec)
	if err != nil {
		t.Fatalf("exported spec is not readable: %v", err)
	}
	if len(specs) != 1 || specs[0].KeyType != "RSA-2048" || len(specs[0].Hostnames) != 1 {
		t.Errorf("exported specs = %+v, want one RSA-2048 spec for example.com", specs)
	}
	if _, err := os.Stat(opts.PublicCertificate); err == nil {
		t.Error("a certificate was generated, want only the spec to be written")
	}
}

func TestRun_ExportSpecFromSpec(t *testing.T) {
	opts, dir := testOptions(t)
	opts.Spec = writeSpecFile(t, dir, "input.yaml", `
- commonName: "Test Root CA"
  certificateAuthority: true
  keyType: "RSA-2048"
  children:
    - commonName: "leaf.example.com"
      keyType: "RSA-2048"
`)
	opts.ExportSpec = filepath.Join(dir, "output.yaml")

	if err := Run(opts); err != nil {
		t.Fatalf("Run() err = %v", err)
	}
	if _, err := os.Stat(opts.ExportSpec); err != nil {
		t.Errorf("expected output spec file: %v", err)
	}
	if got := countFiles(t, dir, "*.cert"); got != 0 {
		t.Errorf("got %d certificates, want none when exporting a spec", got)
	}
}

func TestRun_ExportSpecErrors(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Options, string)
	}{
		{"invalid ports", func(o *Options, dir string) {
			o.ExportSpec = filepath.Join(dir, "out.yaml")
			o.Ports = "not-a-port"
		}},
		{"unwritable path", func(o *Options, dir string) {
			o.ExportSpec = filepath.Join(dir, "missing", "out.yaml")
			o.Chain = "2"
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			opts, dir := testOptions(t)
			tc.mutate(&opts, dir)
			if err := Run(opts); err == nil {
				t.Error("Run() = nil error, want error")
			}
		})
	}
}
