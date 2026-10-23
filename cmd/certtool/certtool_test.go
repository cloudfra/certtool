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
	"io"
	"testing"
	"time"

	"github.com/cloudfra/certtool/internal/certtool"
	"github.com/google/go-cmp/cmp"
)

func newFlagSet() *flag.FlagSet {
	fs := flag.NewFlagSet("certtool", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return fs
}

func TestParseFlagsDefaults(t *testing.T) {
	args, err := parseFlags(newFlagSet(), nil)
	if err != nil {
		t.Fatalf("parseFlags() err = %v", err)
	}
	if diff := cmp.Diff(certtool.DefaultArgs(), args); diff != "" {
		t.Errorf("parseFlags() without flags is not DefaultArgs() (-want +got):\n%s", diff)
	}
}

func TestParseFlags(t *testing.T) {
	args, err := parseFlags(newFlagSet(), []string{
		"--public-certificate", "server.crt",
		"--private-key", "server.key",
		"--ca",
		"--max-path-len", "1",
		"--permitted-dns-domains", "example.com,.internal",
		"--permitted-ip-ranges", "10.0.0.0/8",
		"--common-name", "Acme Root CA",
		"--country", "CA",
		"--organization", "Acme",
		"--organizational-unit", "Security",
		"--locality", "Toronto",
		"--province", "ON",
		"--validity", "48h",
		"--hostnames", "a.example.com,b.example.com",
		"--key-type", "ECDSA-384",
		"--parent-public-certificate", "parent.crt",
		"--parent-private-key", "parent.key",
		"--code-sign",
		"--target", "linux",
		"--pfx-output", "out.pfx",
		"--pfx-password", "secret",
		"--spec", "certs.yaml",
		"--chain", "1,2",
		"--name-prefix", "prod",
		"--output-dir", "certs",
		"--export-spec", "out.yaml",
		"--overwrite",
		"--yubikey",
		"--yubikey-generate-root",
		"--yubikey-serial", "1234567",
		"--yubikey-slot", "82",
		"--yubikey-pin", "123456",
		"--yubikey-management-key", "abcd",
		"--yubikey-touch-policy", "always",
		"--yubikey-overwrite",
		"--encrypt-to", "age1a,age1b",
		"--age-identity-file", "id.txt",
		"--age-yubikey",
		"--version",
	})
	if err != nil {
		t.Fatalf("parseFlags() err = %v", err)
	}

	want := certtool.Args{
		PublicCertificate:       "server.crt",
		PrivateKey:              "server.key",
		CA:                      true,
		MaxPathLen:              1,
		PermittedDNSDomains:     "example.com,.internal",
		PermittedIPRanges:       "10.0.0.0/8",
		CommonName:              "Acme Root CA",
		Country:                 "CA",
		Organization:            "Acme",
		OrganizationalUnit:      "Security",
		Locality:                "Toronto",
		Province:                "ON",
		Validity:                48 * time.Hour,
		Hostnames:               "a.example.com,b.example.com",
		KeyType:                 "ECDSA-384",
		ParentPublicCertificate: "parent.crt",
		ParentPrivateKey:        "parent.key",
		CodeSigning:             true,
		Target:                  "linux",
		PFXOutput:               "out.pfx",
		PFXPassword:             "secret",
		Spec:                    "certs.yaml",
		Chain:                   "1,2",
		NamePrefix:              "prod",
		OutputDir:               "certs",
		ExportSpec:              "out.yaml",
		Overwrite:               true,
		YubiKey:                 true,
		YubiKeyGenerateRoot:     true,
		YubiKeySerial:           "1234567",
		YubiKeySlot:             "82",
		YubiKeyPIN:              "123456",
		YubiKeyManagementKey:    "abcd",
		YubiKeyTouchPolicy:      "always",
		YubiKeyOverwrite:        true,
		EncryptTo:               "age1a,age1b",
		AgeIdentityFile:         "id.txt",
		AgeYubiKey:              true,
		Version:                 true,
	}
	if diff := cmp.Diff(want, args); diff != "" {
		t.Errorf("parseFlags() mismatch (-want +got):\n%s", diff)
	}
}

func TestParseFlagsError(t *testing.T) {
	if _, err := parseFlags(newFlagSet(), []string{"--not-a-flag"}); err == nil {
		t.Error("parseFlags() err = nil, want an error for an unknown flag")
	}
}
