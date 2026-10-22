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
	"os"
	"strings"
	"testing"
)

func TestValidateModesYubiKey(t *testing.T) {
	testCases := []struct {
		name string
		set  func(*Args)
		want string
	}{
		{
			name: "use and generate",
			set:  func(a *Args) { a.YubiKey, a.YubiKeyGenerateRoot = true, true },
			want: "--yubikey and --yubikey-generate-root are mutually exclusive",
		},
		{
			name: "use with parent certificate",
			set:  func(a *Args) { a.YubiKey, a.ParentPublicCertificate = true, "ca.crt" },
			want: "--yubikey and --parent-public-certificate/--parent-private-key are mutually exclusive",
		},
		{
			name: "use with parent key",
			set:  func(a *Args) { a.YubiKey, a.ParentPrivateKey = true, "ca.key" },
			want: "--yubikey and --parent-public-certificate/--parent-private-key are mutually exclusive",
		},
		{
			name: "generate with chain",
			set:  func(a *Args) { a.YubiKeyGenerateRoot, a.Chain = true, "1,1" },
			want: "--yubikey-generate-root cannot be combined with",
		},
		{
			name: "generate with spec",
			set:  func(a *Args) { a.YubiKeyGenerateRoot, a.Spec = true, "certs.yaml" },
			want: "--yubikey-generate-root cannot be combined with",
		},
		{
			name: "generate with code signing",
			set:  func(a *Args) { a.YubiKeyGenerateRoot, a.CodeSigning = true, true },
			want: "--yubikey-generate-root cannot be combined with",
		},
		{
			name: "generate with export",
			set:  func(a *Args) { a.YubiKeyGenerateRoot, a.ExportSpec = true, "out.yaml" },
			want: "--yubikey-generate-root cannot be combined with",
		},
		{
			name: "generate with parent key",
			set:  func(a *Args) { a.YubiKeyGenerateRoot, a.ParentPrivateKey = true, "ca.key" },
			want: "--yubikey-generate-root cannot be combined with",
		},
		{
			name: "touch policy without generate",
			set:  func(a *Args) { a.YubiKey, a.YubiKeyTouchPolicy = true, "cached" },
			want: "only apply to --yubikey-generate-root",
		},
		{
			name: "overwrite without generate",
			set:  func(a *Args) { a.YubiKeyOverwrite = true },
			want: "only apply to --yubikey-generate-root",
		},
		{
			name: "slot without yubikey",
			set:  func(a *Args) { a.YubiKeySlot = "82" },
			want: "need --yubikey or --yubikey-generate-root",
		},
		{
			name: "pin without yubikey",
			set:  func(a *Args) { a.YubiKeyPIN = "123456" },
			want: "need --yubikey or --yubikey-generate-root",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			args := DefaultArgs()
			tc.set(&args)
			err := validateModes(args)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("validateModes() err = %v, want it to contain %q", err, tc.want)
			}
		})
	}
}

func TestValidateModesYubiKeyAllowed(t *testing.T) {
	for name, set := range map[string]func(*Args){
		"yubikey":  func(a *Args) { a.YubiKey = true },
		"chain":    func(a *Args) { a.YubiKey, a.Chain = true, "1,1" },
		"spec":     func(a *Args) { a.YubiKey, a.Spec = true, "certs.yaml" },
		"generate": func(a *Args) { a.YubiKeyGenerateRoot = true },
		"generate opts": func(a *Args) {
			a.YubiKeyGenerateRoot, a.YubiKeyTouchPolicy, a.YubiKeyOverwrite, a.YubiKeySlot = true, "always", true, "82"
		},
		"serial and pin": func(a *Args) {
			a.YubiKey, a.YubiKeySerial, a.YubiKeyPIN = true, "1234567", "123456"
		},
	} {
		t.Run(name, func(t *testing.T) {
			args := DefaultArgs()
			set(&args)
			if err := validateModes(args); err != nil {
				t.Errorf("validateModes() err = %v, want nil", err)
			}
		})
	}
}

func TestYubiKeyConfig(t *testing.T) {
	t.Setenv(YubiKeyPINEnv, "222222")
	t.Setenv(YubiKeyManagementKeyEnv, "ef01")
	args := DefaultArgs()
	args.YubiKey = true
	args.YubiKeySerial, args.YubiKeySlot, args.YubiKeyPIN, args.YubiKeyManagementKey = "1234567", "9a", "111111", "abcd"

	cfg, err := yubiKeyConfig(t.Context(), args)
	if err != nil {
		t.Fatalf("yubiKeyConfig() err = %v", err)
	}
	// Flags take precedence over the environment.
	if cfg.Serial != 1234567 || cfg.Slot != "9a" || cfg.PIN != "111111" || cfg.ManagementKey != "abcd" {
		t.Errorf("yubiKeyConfig() = %+v, want serial 1234567, slot 9a, the PIN and management key from flags", cfg)
	}
	if cfg.BeforeSign == nil {
		t.Error("yubiKeyConfig() did not set BeforeSign")
	}
}

func TestYubiKeyConfigEnvironment(t *testing.T) {
	t.Setenv(YubiKeyPINEnv, "222222")
	t.Setenv(YubiKeyManagementKeyEnv, "ef01")
	args := DefaultArgs()
	args.YubiKey = true

	cfg, err := yubiKeyConfig(t.Context(), args)
	if err != nil {
		t.Fatalf("yubiKeyConfig() err = %v", err)
	}
	if cfg.Serial != 0 || cfg.Slot != "9c" || cfg.PIN != "222222" || cfg.ManagementKey != "ef01" {
		t.Errorf("yubiKeyConfig() = %+v, want serial 0, slot 9c, and the PIN and management key from the environment", cfg)
	}
}

func TestYubiKeyConfigInvalidSerial(t *testing.T) {
	for _, serial := range []string{"abc", "-1", "4294967296"} {
		t.Run(serial, func(t *testing.T) {
			args := DefaultArgs()
			args.YubiKey, args.YubiKeyPIN, args.YubiKeySerial = true, "123456", serial
			if _, err := yubiKeyConfig(t.Context(), args); err == nil || !strings.Contains(err.Error(), "is not a valid serial number") {
				t.Errorf("yubiKeyConfig() with serial %q err = %v, want an invalid serial number error", serial, err)
			}
		})
	}
}

// certtool runs in automation and never prompts, so a missing PIN fails with
// an error that names the flag and the environment variable.
func TestYubiKeyMissingPIN(t *testing.T) {
	t.Setenv(YubiKeyPINEnv, "")
	for _, tc := range []struct {
		mode string
		set  func(*Args)
	}{
		{"--yubikey", func(a *Args) { a.YubiKey = true }},
		{"--yubikey", func(a *Args) { a.YubiKey, a.Chain = true, "1,1" }},
		{"--yubikey-generate-root", func(a *Args) { a.YubiKeyGenerateRoot = true }},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			args := testArgs(t)
			tc.set(&args)
			err := Run(t.Context(), args)
			for _, want := range []string{tc.mode + " needs the YubiKey PIN", "--yubikey-pin", YubiKeyPINEnv} {
				if err == nil || !strings.Contains(err.Error(), want) {
					t.Errorf("Run() err = %v, want it to contain %q", err, want)
				}
			}
			assertNoFiles(t, args.OutputDir)
		})
	}
}

// Without a usable YubiKey (none connected, no PC/SC service, or a build
// without YubiKey support) certtool must fail cleanly and write nothing.
//
// The test selects serial number 1, which no real YubiKey has, so it never
// changes a YubiKey that happens to be plugged into the machine running it.
func TestRunYubiKeyUnavailable(t *testing.T) {
	for name, set := range map[string]func(*Args){
		"yubikey":  func(a *Args) { a.YubiKey = true },
		"chain":    func(a *Args) { a.YubiKey, a.Chain = true, "1,1" },
		"generate": func(a *Args) { a.YubiKeyGenerateRoot = true },
	} {
		t.Run(name, func(t *testing.T) {
			args := testArgs(t)
			args.YubiKeySerial, args.YubiKeyPIN = "1", "123456"
			set(&args)

			if err := Run(t.Context(), args); err == nil {
				t.Error("Run() err = nil, want an error without a usable YubiKey")
			}
			assertNoFiles(t, args.OutputDir)
		})
	}
}

func assertNoFiles(t *testing.T, dir string) {
	t.Helper()

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("wrote %d files, want none", len(entries))
	}
}
