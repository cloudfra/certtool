// Copyright 2026 Cloudfra
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
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	certlib "github.com/cloudfra/certtool/pkg/certtool"
)

func TestRunScenario(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "certs.yaml")

	args := DefaultArgs()
	args.Scenario = "web,mtls,code-sign"
	args.Organization = "Acme"
	args.Country = "CA"
	args.Hostnames = "api.example.com"
	args.Clients = "billing"
	args.KeyType = "ecdsa-384"
	args.Validity = 30 * 24 * time.Hour
	args.Target = "windows11"
	args.ExportSpec = path
	if err := Run(t.Context(), args); err != nil {
		t.Fatalf("Run() err = %v", err)
	}

	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	// The path is quoted when it needs it, as Windows temporary paths do.
	if plain, quoted := "  certtool --spec "+path+" --output-dir certs\n", "  certtool --spec '"+path+"' --output-dir certs\n"; !strings.Contains(string(data), plain) && !strings.Contains(string(data), quoted) {
		t.Errorf("spec does not say how to run it (%q):\n%s", plain, data)
	}
	specs, err := certlib.UnmarshalSpec(data)
	if err != nil {
		t.Fatalf("UnmarshalSpec() err = %v", err)
	}
	if len(specs) != 3 {
		t.Fatalf("got %d top-level entries, want 3 (web, mtls, code-sign)", len(specs))
	}

	server := specs[0].Children[0].Children[0]
	if server.KeyType != "ECDSA-384" || server.Validity != "720h" || server.Country != "CA" {
		t.Errorf("server keyType, validity, country = %q, %q, %q; want ECDSA-384, 720h, CA from the flags", server.KeyType, server.Validity, server.Country)
	}
	// Subject fields left at certtool's defaults stay out of the spec.
	if server.Locality != "" || server.Province != "" || server.OrganizationalUnit != "" {
		t.Errorf("server has default subject fields locality %q, province %q, OU %q; want none", server.Locality, server.Province, server.OrganizationalUnit)
	}
	if codeSign := specs[2]; codeSign.Target != "windows11" || codeSign.PFXPasswordEnv != PFXPasswordEnv || codeSign.PFXPassword != "" {
		t.Errorf("code-sign target %q, pfxPasswordEnv %q, pfxPassword %q; want windows11, %s, and no password", codeSign.Target, codeSign.PFXPasswordEnv, codeSign.PFXPassword, PFXPasswordEnv)
	}
}

func TestRunScenarioYubiKey(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "certs.yaml")

	args := DefaultArgs()
	args.Scenario = "web"
	args.Hostnames = "api.example.com"
	args.YubiKey = true
	args.ExportSpec = path
	// The YubiKey is not opened: the spec only leaves the root out.
	if err := Run(t.Context(), args); err != nil {
		t.Fatalf("Run() err = %v", err)
	}

	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "certtool --yubikey --spec") {
		t.Errorf("spec does not say to run it with --yubikey:\n%s", data)
	}
	specs, err := certlib.UnmarshalSpec(data)
	if err != nil {
		t.Fatalf("UnmarshalSpec() err = %v", err)
	}
	if got := specs[0].CommonName; got != "cloudfra Web Issuing CA" {
		t.Errorf("top-level entry = %q, want the issuing CA, because the root is on the YubiKey", got)
	}
}

func TestRunScenarioErrors(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		edit func(*Args)
		want string
	}{
		{"unknown scenario", func(a *Args) { a.Scenario = "web,nomad" }, `--scenario "nomad"`},
		{"common name", func(a *Args) { a.CommonName = "x" }, "--common-name does not apply"},
		{"ca", func(a *Args) { a.CA = true }, "--ca does not apply"},
		{"pfx password", func(a *Args) { a.PFXPassword = "secret" }, "--pfx-password does not apply"},
		{"output dir with export spec", func(a *Args) { a.OutputDir = "certs" }, "--output-dir does not apply to --scenario with --export-spec"},
		{"spec", func(a *Args) { a.Spec = "certs.yaml" }, "--spec does not apply"},
		{"chain", func(a *Args) { a.Chain = "1,1" }, "--chain does not apply"},
		{"yubikey pin", func(a *Args) { a.YubiKey = true; a.YubiKeyPIN = "123456" }, "--yubikey-pin does not apply"},
		{"encrypt to", func(a *Args) { a.EncryptTo = "age1..." }, "--encrypt-to does not apply"},
		{"age yubikey", func(a *Args) { a.AgeYubiKey = true }, "--age-yubikey does not apply"},
		{"target without code-sign", func(a *Args) { a.Target = "linux" }, "--target does not apply"},
		{"clients without a client scenario", func(a *Args) { a.Clients = "billing" }, "--clients does not apply"},
		{"hostnames with only code-sign", func(a *Args) { a.Scenario = "code-sign" }, "--hostnames does not apply"},
		{"web without hostnames", func(a *Args) { a.Hostnames = "" }, "--scenario web needs --hostnames"},
		{"mtls without clients", func(a *Args) { a.Scenario = "mtls" }, "--scenario mtls needs --clients"},
		{"active directory without hostnames", func(a *Args) { a.Scenario = "active-directory"; a.Hostnames = "" }, "FQDN of each domain controller"},
		{"android signing with yubikey", func(a *Args) { a.Scenario = "android-signing"; a.Hostnames = ""; a.YubiKey = true }, "cannot be combined with --yubikey"},
		{"bad hostname", func(a *Args) { a.Hostnames = "*.com" }, "--hostnames"},
		{"bad key type", func(a *Args) { a.KeyType = "DSA-1024" }, "--key-type"},
		{"bad validity", func(a *Args) { a.Validity = -time.Hour }, "--validity"},
		{"no organization", func(a *Args) { a.Organization = "" }, "--organization"},
		{"twice", func(a *Args) { a.Scenario = "web,web" }, "given twice"},
		{"newline in organization", func(a *Args) { a.Organization = "Acme\n- commonName: Evil Root\n#" }, "--organization"},
		{"newline in clients", func(a *Args) { a.Scenario = "mtls"; a.Clients = "alice\n- commonName: Evil Root\n#" }, "--clients"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			args := DefaultArgs()
			args.Scenario = "web"
			args.Hostnames = "example.com"
			args.ExportSpec = filepath.Join(t.TempDir(), "certs.yaml")
			tc.edit(&args)

			err := Run(t.Context(), args)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("Run() err = %v, want an error containing %q", err, tc.want)
			}
		})
	}
}

// TestWriteSpecStdout checks that --export-spec - writes the spec to standard
// output. It replaces os.Stdout, so it cannot run in parallel.
func TestWriteSpecStdout(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout := os.Stdout
	os.Stdout = w
	t.Cleanup(func() { os.Stdout = stdout })

	args := DefaultArgs()
	args.Scenario = "local-dev"
	args.ExportSpec = "-"
	runErr := Run(t.Context(), args)
	os.Stdout = stdout
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if runErr != nil {
		t.Fatalf("Run() err = %v", runErr)
	}

	data, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := certlib.UnmarshalSpec(data); err != nil {
		t.Errorf("standard output is not a spec: %v\n%s", err, data)
	}
	if _, err := os.Stat("-"); err == nil {
		t.Error(`Run() wrote a file named "-"`)
	}
}

// TestRunScenarioGenerates checks that --scenario without --export-spec
// writes the spec next to the certificates and generates them, and that it
// can run again.
func TestRunScenarioGenerates(t *testing.T) {
	t.Setenv(PFXPasswordEnv, "correct horse battery staple")
	dir := filepath.Join(t.TempDir(), "certs")
	args := DefaultArgs()
	args.Scenario = "android-signing"
	args.Organization = "Acme"
	args.OrganizationalUnit = "Mobile"
	args.OutputDir = dir
	if err := Run(t.Context(), args); err != nil {
		t.Fatalf("Run() err = %v", err)
	}

	specPath := filepath.Join(dir, "android-signing.yaml")
	data, err := os.ReadFile(filepath.Clean(specPath))
	if err != nil {
		t.Fatalf("the spec was not written: %v", err)
	}
	for _, want := range []string{
		"#   certtool --scenario android-signing --organization Acme --organizational-unit Mobile --output-dir ",
		"# which also generated the certificates. To change them, edit this file, then run:\n#   certtool --spec ",
	} {
		if !strings.Contains(string(data), want) {
			t.Errorf("spec header does not contain %q:\n%s", want, data)
		}
	}
	for _, name := range []string{"android-signing.crt", "android-signing.key", "android-signing.pfx"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("%s was not generated: %v", name, err)
		}
	}

	// The same command again reuses everything.
	if err := Run(t.Context(), args); err != nil {
		t.Fatalf("second Run() err = %v", err)
	}

	// An edited spec is never replaced.
	edited := slices.Concat(data, []byte("- commonName: extra\n  filename: extra\n"))
	if err := os.WriteFile(specPath, edited, 0o600); err != nil { //nolint:gosec // specPath is a file the test created.
		t.Fatal(err)
	}
	if err := Run(t.Context(), args); err == nil || !strings.Contains(err.Error(), "certtool --spec "+specPath) {
		t.Errorf("Run() with an edited spec err = %v, want one that says to run --spec", err)
	}

	// Which --spec then generates.
	specArgs := DefaultArgs()
	specArgs.Spec, specArgs.OutputDir = specPath, dir
	if err := Run(t.Context(), specArgs); err != nil {
		t.Fatalf("Run(--spec) err = %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "extra.crt")); err != nil {
		t.Errorf("the edited entry was not generated: %v", err)
	}
}
