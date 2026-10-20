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
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// setFlags sets command line flags for the duration of the test.
func setFlags(t *testing.T, values map[string]string) {
	t.Helper()

	for name, value := range values {
		f := flag.Lookup(name)
		if f == nil {
			t.Fatalf("flag --%s does not exist", name)
		}
		orig := f.Value.String()
		if err := flag.Set(name, value); err != nil {
			t.Fatalf("flag.Set(%s, %s) got error, %s", name, value, err)
		}
		t.Cleanup(func() {
			if err := flag.Set(name, orig); err != nil {
				t.Errorf("restoring flag --%s got error, %s", name, err)
			}
		})
	}
}

func TestValidateModeFlagsYubiKey(t *testing.T) {
	testCases := []struct {
		name  string
		flags map[string]string
		want  string
	}{
		{
			name:  "use and generate",
			flags: map[string]string{"yubikey": "true", "yubikey-generate-root": "true"},
			want:  "--yubikey and --yubikey-generate-root are mutually exclusive",
		},
		{
			name:  "use with parent certificate",
			flags: map[string]string{"yubikey": "true", "parent-public-certificate": "ca.crt"},
			want:  "--yubikey and --parent-public-certificate/--parent-private-key are mutually exclusive",
		},
		{
			name:  "use with parent key",
			flags: map[string]string{"yubikey": "true", "parent-private-key": "ca.key"},
			want:  "--yubikey and --parent-public-certificate/--parent-private-key are mutually exclusive",
		},
		{
			name:  "generate with chain",
			flags: map[string]string{"yubikey-generate-root": "true", "chain": "1,1"},
			want:  "--yubikey-generate-root cannot be combined with",
		},
		{
			name:  "generate with spec",
			flags: map[string]string{"yubikey-generate-root": "true", "spec": "certs.yaml"},
			want:  "--yubikey-generate-root cannot be combined with",
		},
		{
			name:  "generate with code signing",
			flags: map[string]string{"yubikey-generate-root": "true", "code-sign": "true"},
			want:  "--yubikey-generate-root cannot be combined with",
		},
		{
			name:  "generate with export",
			flags: map[string]string{"yubikey-generate-root": "true", "export-spec": "out.yaml"},
			want:  "--yubikey-generate-root cannot be combined with",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			setFlags(t, tc.flags)
			err := validateModeFlags()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("validateModeFlags() err = %v, want it to contain %q", err, tc.want)
			}
		})
	}
}

func TestValidateModeFlagsYubiKeyAllowed(t *testing.T) {
	for _, flags := range []map[string]string{
		{"yubikey": "true"},
		{"yubikey": "true", "chain": "1,1"},
		{"yubikey": "true", "spec": "certs.yaml"},
		{"yubikey-generate-root": "true"},
	} {
		t.Run(fmt.Sprint(flags), func(t *testing.T) {
			setFlags(t, flags)
			if err := validateModeFlags(); err != nil {
				t.Errorf("validateModeFlags() with %v err = %v, want nil", flags, err)
			}
		})
	}
}

func TestYubiKeyConfig(t *testing.T) {
	setFlags(t, map[string]string{"yubikey-serial": "1234567", "yubikey-slot": "9a", "yubikey-pin": "111111", "yubikey-management-key": "abcd"})
	t.Setenv(yubiKeyPINEnv, "222222")
	t.Setenv(yubiKeyManagementKeyEnv, "ef01")

	cfg, err := yubiKeyConfig()
	if err != nil {
		t.Fatalf("yubiKeyConfig() err = %v", err)
	}
	// Flags take precedence over the environment.
	if cfg.Serial != 1234567 || cfg.Slot != "9a" || cfg.PIN != "111111" || cfg.ManagementKey != "abcd" {
		t.Errorf("yubiKeyConfig() = %+v, want serial 1234567, slot 9a, the PIN and management key from flags", cfg)
	}
	if cfg.PINPrompt == nil || cfg.BeforeSign == nil {
		t.Error("yubiKeyConfig() did not set PINPrompt and BeforeSign")
	}
}

func TestYubiKeyConfigEnvironment(t *testing.T) {
	t.Setenv(yubiKeyPINEnv, "222222")
	t.Setenv(yubiKeyManagementKeyEnv, "ef01")

	cfg, err := yubiKeyConfig()
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
			setFlags(t, map[string]string{"yubikey-serial": serial})
			if _, err := yubiKeyConfig(); err == nil || !strings.Contains(err.Error(), "is not a valid serial number") {
				t.Errorf("yubiKeyConfig() with serial %q err = %v, want an invalid serial number error", serial, err)
			}
		})
	}
}

func TestPromptYubiKeyPINWithoutTerminal(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := errors.Join(r.Close(), w.Close()); err != nil {
			t.Errorf("closing pipe got error, %s", err)
		}
	})
	origStdin := os.Stdin
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = origStdin })

	if _, err := promptYubiKeyPIN(); err == nil || !strings.Contains(err.Error(), yubiKeyPINEnv) {
		t.Errorf("promptYubiKeyPIN() err = %v, want it to explain how to provide the PIN", err)
	}
}

// Without a usable YubiKey (none connected, no PC/SC service, or a build
// without YubiKey support) certtool must fail cleanly and write nothing.
//
// The test selects serial number 1, which no real YubiKey has, so it never
// changes a YubiKey that happens to be plugged into the machine running it.
func TestCerttoolMainYubiKeyUnavailable(t *testing.T) {
	for _, mode := range []map[string]string{
		{"yubikey": "true"},
		{"yubikey": "true", "chain": "1,1"},
		{"yubikey-generate-root": "true"},
	} {
		t.Run(fmt.Sprint(mode), func(t *testing.T) {
			dir := t.TempDir()
			setFlags(t, mode)
			setFlags(t, map[string]string{
				"public-certificate": filepath.Join(dir, "app.cert"),
				"private-key":        filepath.Join(dir, "app.key"),
				"output-dir":         dir,
				"yubikey-serial":     "1",
			})

			if got := certtoolMain(); got != 1 {
				t.Errorf("certtoolMain() with %v = %d, want 1", mode, got)
			}
			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 0 {
				t.Errorf("certtoolMain() with %v wrote %d files, want none", mode, len(entries))
			}
		})
	}
}
