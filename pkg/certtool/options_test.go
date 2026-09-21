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
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestDefaultOptions(t *testing.T) {
	t.Parallel()
	got := DefaultOptions()
	want := Options{
		PublicCertificate:  "app.cert",
		PrivateKey:         "app.key",
		Country:            "US",
		Organization:       "cloudfra",
		OrganizationalUnit: "gows",
		Locality:           "Seattle",
		Province:           "WA",
		Validity:           time.Hour * 24 * 365,
		PFXOutput:          "codesign.pfx",
		OutputDir:          ".",
	}
	if got != want {
		t.Errorf("DefaultOptions() = %+v, want %+v", got, want)
	}
}

func TestOptionsArgs(t *testing.T) {
	t.Parallel()
	opts := DefaultOptions()
	opts.CA = true
	opts.CommonName = "my-service.example.com"
	opts.Validity = 48 * time.Hour
	opts.Hostnames = "a.example.com, b.example.com"
	opts.Ports = "80,443"
	opts.KeyType = "ecdsa-384"
	opts.CodeSigning = true
	opts.Target = "linux"
	opts.PFXPassword = "secret"

	args, err := opts.args()
	if err != nil {
		t.Fatalf("args() err = %v", err)
	}
	if !args.CA || args.CommonName != "my-service.example.com" || args.Validity != 48*time.Hour {
		t.Errorf("args = %+v, want CA, common name and 48h validity carried over", args)
	}
	if !slices.Equal(args.Hostnames, []string{"a.example.com", "b.example.com"}) || !slices.Equal(args.Ports, []int{80, 443}) {
		t.Errorf("args hostnames/ports = %v/%v", args.Hostnames, args.Ports)
	}
	if args.KeyType == nil || args.KeyType.Algorithm != ecdsaAlgorithm || args.KeyType.KeyLength != 384 {
		t.Errorf("args.KeyType = %+v, want ECDSA-384", args.KeyType)
	}
	if !args.CodeSigning || args.Target != "linux" || args.PFXPassword != "secret" {
		t.Errorf("args = %+v, want code signing fields carried over", args)
	}
	if args.Country != "US" || args.Organization != "cloudfra" || args.OrganizationalUnit != "gows" {
		t.Errorf("args subject = %+v, want the default subject fields", args)
	}
}

func TestOptionsArgsDefaults(t *testing.T) {
	t.Parallel()
	opts := DefaultOptions()
	args, err := opts.args()
	if err != nil {
		t.Fatalf("args() err = %v", err)
	}
	if args.CA {
		t.Error("args.CA = true, want false")
	}
	if args.Validity != time.Hour*24*365 {
		t.Errorf("args.Validity = %v, want 8760h (1 year)", args.Validity)
	}
	if args.CommonName != "" {
		t.Errorf("args.CommonName = %q, want empty (defaults to organization when generating)", args.CommonName)
	}
	if args.KeyType == nil || args.KeyType.Algorithm != rsaAlgorithm || args.KeyType.KeyLength != 2048 {
		t.Errorf("args.KeyType = %+v, want RSA-2048 for TLS", args.KeyType)
	}
}

// A code signing certificate takes its key type from the platform profile
// unless one is chosen explicitly.
func TestOptionsArgsCodeSigningKeyType(t *testing.T) {
	t.Parallel()
	opts := DefaultOptions()
	opts.CodeSigning = true
	args, err := opts.args()
	if err != nil {
		t.Fatalf("args() err = %v", err)
	}
	if args.KeyType != nil {
		t.Errorf("args.KeyType = %+v, want nil so the profile default applies", args.KeyType)
	}
}

func TestOptionsArgsExplicitECDSAOnWindows7(t *testing.T) {
	logs := captureLogs(t)
	opts := DefaultOptions()
	opts.CodeSigning = true
	opts.KeyType = "ECDSA-256"
	opts.Target = "windows7"

	args, err := opts.args()
	if err != nil {
		t.Fatalf("args() err = %v", err)
	}
	if args.KeyType == nil || args.KeyType.Algorithm != ecdsaAlgorithm || args.KeyType.KeyLength != 256 {
		t.Errorf("args.KeyType = %+v, want ECDSA-256", args.KeyType)
	}
	if !strings.Contains(logs.String(), "not supported by Windows 7 signtool.exe") {
		t.Errorf("logs = %q, want the Windows 7 ECDSA warning", logs.String())
	}
}

func TestOptionsArgsExplicitECDSANoTarget(t *testing.T) {
	logs := captureLogs(t)
	opts := DefaultOptions()
	opts.CodeSigning = true
	opts.KeyType = "ECDSA-256"

	// With no target the effective target is windows10, so there is nothing to warn about.
	args, err := opts.args()
	if err != nil {
		t.Fatalf("args() err = %v", err)
	}
	if args.KeyType == nil || args.KeyType.Algorithm != ecdsaAlgorithm || args.KeyType.KeyLength != 256 {
		t.Errorf("args.KeyType = %+v, want ECDSA-256", args.KeyType)
	}
	if logs.Len() != 0 {
		t.Errorf("logs = %q, want no warning", logs.String())
	}
}

func TestOptionsArgsErrors(t *testing.T) {
	t.Parallel()
	missing := filepath.Join(t.TempDir(), "missing")
	tests := []struct {
		name   string
		mutate func(*Options)
	}{
		{"invalid key type", func(o *Options) { o.KeyType = "not-a-real-key-type" }},
		{"negative validity", func(o *Options) { o.Validity = -24 * time.Hour }},
		{"zero validity", func(o *Options) { o.Validity = 0 }},
		{"invalid ports", func(o *Options) { o.Ports = "abc" }},
		{"missing parent certificate", func(o *Options) {
			o.ParentPublicCertificate = missing + ".cert"
			o.ParentPrivateKey = missing + ".key"
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			opts := DefaultOptions()
			tc.mutate(&opts)
			if _, err := opts.args(); err == nil {
				t.Error("args() = nil error, want error")
			}
		})
	}
}

func TestOptionsSpecs(t *testing.T) {
	t.Parallel()
	opts := DefaultOptions()
	opts.Hostnames = "example.com"
	opts.Ports = "443"
	opts.KeyType = "ECDSA-256"

	specs, err := opts.flagsToSpec()
	if err != nil {
		t.Fatalf("flagsToSpec() err = %v", err)
	}
	if len(specs) != 1 {
		t.Fatalf("got %d specs, want 1", len(specs))
	}
	s := specs[0]
	if s.CommonName != "cloudfra" {
		t.Errorf("CommonName = %q, want the organization when no common name is set", s.CommonName)
	}
	if s.KeyType != "ECDSA-256" || s.Validity != "8760h0m0s" || !slices.Equal(s.Hostnames, []string{"example.com"}) || !slices.Equal(s.Ports, []int{443}) {
		t.Errorf("spec = %+v, want the options carried over", s)
	}
}

// An unset key type is exported as the value the tool would use, so the spec
// generates the same certificate the flags would have.
func TestOptionsSpecsResolvesKeyType(t *testing.T) {
	t.Parallel()
	tls := DefaultOptions()
	specs, err := tls.flagsToSpec()
	if err != nil {
		t.Fatalf("flagsToSpec() err = %v", err)
	}
	if specs[0].KeyType != "RSA-2048" {
		t.Errorf("TLS KeyType = %q, want RSA-2048", specs[0].KeyType)
	}

	signing := DefaultOptions()
	signing.CodeSigning = true
	specs, err = signing.flagsToSpec()
	if err != nil {
		t.Fatalf("flagsToSpec() err = %v", err)
	}
	if specs[0].KeyType != "" {
		t.Errorf("code signing KeyType = %q, want empty so the profile default applies", specs[0].KeyType)
	}
}

func TestOptionsSpecsInvalidPorts(t *testing.T) {
	t.Parallel()
	opts := DefaultOptions()
	opts.Ports = "not-a-port"
	if _, err := opts.flagsToSpec(); err == nil {
		t.Error("flagsToSpec() = nil error, want error for invalid ports")
	}
}

func TestChainWidths(t *testing.T) {
	t.Parallel()
	tests := []struct {
		input   string
		want    []int
		wantErr bool
	}{
		{input: "3", want: []int{3}},
		{input: "1,2,3", want: []int{1, 2, 3}},
		{input: " 1 , 2 ", want: []int{1, 2}},
		{input: "2,abc", wantErr: true},
		{input: "1,,2", wantErr: true},
		{input: "", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			t.Parallel()
			got, err := chainWidths(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("chainWidths(%q) = nil error, want error", tc.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("chainWidths(%q) err = %v", tc.input, err)
			}
			if !slices.Equal(got, tc.want) {
				t.Errorf("chainWidths(%q) = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}

func TestStringToKeyType(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		input         string
		wantAlgorithm string
		wantKeyLength int
	}{
		{input: "", wantAlgorithm: rsaAlgorithm, wantKeyLength: 2048},
		{input: rsaAlgorithm, wantAlgorithm: rsaAlgorithm, wantKeyLength: 2048},
		{input: "RSA-2048", wantAlgorithm: rsaAlgorithm, wantKeyLength: 2048},
		{input: "rsa-4096", wantAlgorithm: rsaAlgorithm, wantKeyLength: 4096},
		{input: "ecdsa-384", wantAlgorithm: ecdsaAlgorithm, wantKeyLength: 384},
		{input: "ECDSA-521", wantAlgorithm: ecdsaAlgorithm, wantKeyLength: 521},
		{input: ecdsaAlgorithm, wantAlgorithm: ecdsaAlgorithm, wantKeyLength: 521},
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
	t.Parallel()
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
			if _, _, err := stringToKeyType(tc); err == nil {
				t.Errorf("stringToKeyType(%q) = nil error, want error", tc)
			}
		})
	}
}

func TestSplitStrings(t *testing.T) {
	t.Parallel()
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
			if got := splitStrings(tc.input); !slices.Equal(got, tc.want) {
				t.Errorf("splitStrings(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestSplitInts(t *testing.T) {
	t.Parallel()
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
			if !slices.Equal(got, tc.want) {
				t.Errorf("splitInts(%q) = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}
