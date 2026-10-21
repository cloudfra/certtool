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
	"os"
	"path/filepath"
	"strings"
	"testing"

	certlib "github.com/cloudfra/certtool/pkg/certtool"
	"software.sslmate.com/src/go-pkcs12"
)

func assertPFXPassword(t *testing.T, path, password string) {
	t.Helper()

	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := pkcs12.Decode(data, password); err != nil {
		t.Errorf("pkcs12.Decode(%s, %q) err = %v", path, password, err)
	}
}

// The password can come from the environment, keeping it off the command line
// where other users can see it.
func TestRunPFXPasswordFromEnvironment(t *testing.T) {
	t.Setenv(PFXPasswordEnv, "from-env")
	args := testArgs(t)
	args.CodeSigning, args.Target = true, defaultCodeSignTarget
	if err := Run(args); err != nil {
		t.Fatalf("Run() err = %v", err)
	}
	assertPFXPassword(t, args.PFXOutput, "from-env")
}

func TestRunPFXPasswordFlagOverridesEnvironment(t *testing.T) {
	t.Setenv(PFXPasswordEnv, "from-env")
	args := testArgs(t)
	args.CodeSigning, args.Target, args.PFXPassword = true, defaultCodeSignTarget, "from-flag"
	if err := Run(args); err != nil {
		t.Fatalf("Run() err = %v", err)
	}
	assertPFXPassword(t, args.PFXOutput, "from-flag")
}

// --export-spec must never copy a password into the file it writes.
func TestRunExportSpecOmitsPFXPassword(t *testing.T) {
	for name, set := range map[string]func(t *testing.T, a *Args){
		"flag":        func(_ *testing.T, a *Args) { a.PFXPassword = "s3cret-value" },
		"environment": func(t *testing.T, _ *Args) { t.Setenv(PFXPasswordEnv, "s3cret-value") },
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(PFXPasswordEnv, "")
			args := testArgs(t)
			args.CodeSigning, args.Target = true, defaultCodeSignTarget
			args.ExportSpec = filepath.Join(t.TempDir(), "out.yaml")
			set(t, &args)
			if err := Run(args); err != nil {
				t.Fatalf("Run() err = %v", err)
			}

			data, err := os.ReadFile(args.ExportSpec)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(data), "s3cret-value") {
				t.Errorf("exported spec contains the password:\n%s", data)
			}
			specs, err := certlib.UnmarshalSpec(data)
			if err != nil {
				t.Fatal(err)
			}
			if got := specs[0].PFXPasswordEnv; got != PFXPasswordEnv {
				t.Errorf("pfxPasswordEnv = %q, want %q", got, PFXPasswordEnv)
			}
		})
	}
}

func TestRunExportSpecWithoutPFXPassword(t *testing.T) {
	t.Setenv(PFXPasswordEnv, "")
	args := testArgs(t)
	args.CodeSigning, args.Target = true, defaultCodeSignTarget
	args.ExportSpec = filepath.Join(t.TempDir(), "out.yaml")
	if err := Run(args); err != nil {
		t.Fatalf("Run() err = %v", err)
	}
	data, err := os.ReadFile(args.ExportSpec)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "pfxPassword") {
		t.Errorf("exported spec mentions a password although none was set:\n%s", data)
	}
}

// Re-exporting a spec replaces its plain text passwords with pfxPasswordEnv,
// and the result generates a .pfx with the same password.
func TestRunSpecExportReplacesPFXPasswords(t *testing.T) {
	dir := t.TempDir()
	spec := writeSpec(t, dir, "in.yaml", "- commonName: Signing\n  codeSigning: true\n  pfxPassword: s3cret-value\n  filename: sign\n")
	args := testArgs(t)
	args.Spec, args.ExportSpec = spec, filepath.Join(dir, "out.yaml")
	if err := Run(args); err != nil {
		t.Fatalf("Run() export err = %v", err)
	}
	data, err := os.ReadFile(args.ExportSpec)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "s3cret-value") || !strings.Contains(string(data), "pfxPasswordEnv: "+PFXPasswordEnv) {
		t.Fatalf("exported spec = \n%s\nwant pfxPasswordEnv instead of the password", data)
	}

	t.Setenv(PFXPasswordEnv, "s3cret-value")
	gen := testArgs(t)
	gen.Spec = args.ExportSpec
	if err := Run(gen); err != nil {
		t.Fatalf("Run() generate err = %v", err)
	}
	assertPFXPassword(t, filepath.Join(gen.OutputDir, "sign.pfx"), "s3cret-value")
}
