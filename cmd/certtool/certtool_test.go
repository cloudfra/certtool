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
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cloudfra/certtool/pkg/certtool"
)

func TestParseFlagsDefaults(t *testing.T) {
	opts, showVersion, err := parseFlags(nil, io.Discard)
	if err != nil {
		t.Fatalf("parseFlags() err = %v", err)
	}
	if showVersion {
		t.Error("showVersion = true, want false")
	}
	if want := certtool.DefaultOptions(); opts != want {
		t.Errorf("opts = %+v, want the library defaults %+v", opts, want)
	}
}

// TestParseFlagsMapsEveryFlag sets every flag to a non-default value and checks
// it lands in the matching option, so a flag that is not wired up fails here.
func TestParseFlagsMapsEveryFlag(t *testing.T) {
	args := []string{
		"--public-certificate", "p.cert",
		"--private-key", "p.key",
		"--ca",
		"--common-name", "cn",
		"--country", "CA",
		"--organization", "Org",
		"--organizational-unit", "OU",
		"--locality", "Loc",
		"--province", "Prov",
		"--validity", "48h",
		"--hostnames", "a.example.com,b.example.com",
		"--key-type", "ECDSA-256",
		"--ports", "80,443",
		"--parent-public-certificate", "parent.cert",
		"--parent-private-key", "parent.key",
		"--code-sign",
		"--target", "linux",
		"--pfx-output", "out.pfx",
		"--pfx-password", "secret",
		"--spec", "spec.yaml",
		"--chain", "1,2",
		"--name-prefix", "prod",
		"--output-dir", "out",
		"--export-spec", "export.yaml",
	}
	want := certtool.Options{
		PublicCertificate:       "p.cert",
		PrivateKey:              "p.key",
		CA:                      true,
		CommonName:              "cn",
		Country:                 "CA",
		Organization:            "Org",
		OrganizationalUnit:      "OU",
		Locality:                "Loc",
		Province:                "Prov",
		Validity:                48 * time.Hour,
		Hostnames:               "a.example.com,b.example.com",
		KeyType:                 "ECDSA-256",
		Ports:                   "80,443",
		ParentPublicCertificate: "parent.cert",
		ParentPrivateKey:        "parent.key",
		CodeSigning:             true,
		Target:                  "linux",
		PFXOutput:               "out.pfx",
		PFXPassword:             "secret",
		Spec:                    "spec.yaml",
		Chain:                   "1,2",
		NamePrefix:              "prod",
		OutputDir:               "out",
		ExportSpec:              "export.yaml",
	}

	// Guard the test itself: every option must be covered by a flag above.
	wantValue := reflect.ValueOf(want)
	for i := 0; i < wantValue.NumField(); i++ {
		if wantValue.Field(i).IsZero() {
			t.Fatalf("test does not set Options.%s; add its flag to args", wantValue.Type().Field(i).Name)
		}
	}

	got, _, err := parseFlags(args, io.Discard)
	if err != nil {
		t.Fatalf("parseFlags() err = %v", err)
	}
	if got != want {
		t.Errorf("opts = %+v, want %+v", got, want)
	}
}

func TestParseFlagsVersion(t *testing.T) {
	_, showVersion, err := parseFlags([]string{"--version"}, io.Discard)
	if err != nil {
		t.Fatalf("parseFlags() err = %v", err)
	}
	if !showVersion {
		t.Error("showVersion = false, want true for --version")
	}
}

func TestParseFlagsErrors(t *testing.T) {
	for _, args := range [][]string{{"--no-such-flag"}, {"--validity", "soon"}, {"--ca=maybe"}} {
		if _, _, err := parseFlags(args, io.Discard); err == nil {
			t.Errorf("parseFlags(%v) = nil error, want error", args)
		}
	}
}

func TestRunVersion(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if got := run([]string{"--version"}, &stdout, &stderr); got != 0 {
		t.Errorf("run(--version) = %d, want 0", got)
	}
	if !strings.HasPrefix(stdout.String(), "certtool ") {
		t.Errorf("stdout = %q, want the version banner", stdout.String())
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("write failed") }

func TestRunVersionWriteFailure(t *testing.T) {
	if got := run([]string{"--version"}, failingWriter{}, io.Discard); got != 1 {
		t.Errorf("run(--version) = %d, want 1 when stdout cannot be written", got)
	}
}

func TestRunHelp(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if got := run([]string{"-h"}, &stdout, &stderr); got != 0 {
		t.Errorf("run(-h) = %d, want 0", got)
	}
	if !strings.Contains(stderr.String(), "-chain") {
		t.Errorf("stderr = %q, want usage listing the flags", stderr.String())
	}
}

func TestRunFlagError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if got := run([]string{"--no-such-flag"}, &stdout, &stderr); got != 2 {
		t.Errorf("run(--no-such-flag) = %d, want 2", got)
	}
	if !strings.Contains(stderr.String(), "no-such-flag") {
		t.Errorf("stderr = %q, want the flag error", stderr.String())
	}
}

func TestRunGeneratesCertificate(t *testing.T) {
	dir := t.TempDir()
	cert, key := filepath.Join(dir, "app.cert"), filepath.Join(dir, "app.key")
	if got := run([]string{"--public-certificate", cert, "--private-key", key}, io.Discard, io.Discard); got != 0 {
		t.Fatalf("run() = %d, want 0", got)
	}
	for _, path := range []string{cert, key} {
		if _, err := os.Stat(path); err != nil {
			t.Errorf("expected %s to be written: %v", path, err)
		}
	}
}

func TestRunChain(t *testing.T) {
	dir := t.TempDir()
	if got := run([]string{"--chain", "1,2", "--output-dir", dir}, io.Discard, io.Discard); got != 0 {
		t.Fatalf("run(--chain 1,2) = %d, want 0", got)
	}
	certs, err := filepath.Glob(filepath.Join(dir, "*.cert"))
	if err != nil || len(certs) != 3 {
		t.Errorf("got %d certificates (err %v), want 3", len(certs), err)
	}
}

func TestRunFailureExitsOne(t *testing.T) {
	for _, args := range [][]string{
		{"--key-type", "not-a-real-key-type"},
		{"--chain", "2", "--spec", "spec.yaml"},
		{"--validity", "-1h"},
	} {
		if got := run(args, io.Discard, io.Discard); got != 1 {
			t.Errorf("run(%v) = %d, want 1", args, got)
		}
	}
}
