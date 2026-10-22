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
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"software.sslmate.com/src/go-pkcs12"
)

func reuseSpec(leaves ...string) []CertificateSpec {
	root := CertificateSpec{CommonName: "Reuse Root CA", CertificateAuthority: true, KeyType: testSpecECDSA256, Filename: "root"}
	for _, leaf := range leaves {
		root.Children = append(root.Children, CertificateSpec{CommonName: leaf, KeyType: testSpecECDSA256, Filename: leaf})
	}
	return []CertificateSpec{root}
}

func readFiles(t *testing.T, dir string, names ...string) map[string][]byte {
	t.Helper()

	files := map[string][]byte{}
	for _, name := range names {
		data, err := fs.ReadFile(os.DirFS(dir), name)
		if err != nil {
			t.Fatal(err)
		}
		files[name] = data
	}
	return files
}

func reusedNames(out []GenerationOutput) (reused, generated []string) {
	for _, o := range out {
		if o.Reused {
			reused = append(reused, o.CommonName)
		} else {
			generated = append(generated, o.CommonName)
		}
	}
	return reused, generated
}

// Running a spec again keeps the files it already wrote, and extending it adds
// certificates signed by the existing CA instead of resetting the hierarchy.
func TestGenerateFromSpec_ReusesExistingFiles(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if _, err := GenerateFromSpec(reuseSpec("api"), dir); err != nil {
		t.Fatal(err)
	}
	before := readFiles(t, dir, "root.crt", "root.key", "api.crt", "api.key")

	out, err := GenerateFromSpec(reuseSpec("api", "web"), dir)
	if err != nil {
		t.Fatalf("GenerateFromSpec() extended err = %v", err)
	}
	reused, generated := reusedNames(out)
	if strings.Join(reused, ",") != "Reuse Root CA,api" || strings.Join(generated, ",") != "web" {
		t.Errorf("reused %v and generated %v, want the root and api reused and web generated", reused, generated)
	}
	after := readFiles(t, dir, "root.crt", "root.key", "api.crt", "api.key")
	for name := range before {
		if !bytes.Equal(before[name], after[name]) {
			t.Errorf("%s changed, want it reused", name)
		}
	}

	root := parseCertificatePEM(t, after["root.crt"])
	web := parseCertificatePEM(t, readFiles(t, dir, "web.crt")["web.crt"])
	if err := web.CheckSignatureFrom(root); err != nil {
		t.Errorf("the new web certificate is not signed by the reused root: %v", err)
	}
}

func TestGenerateFromSpec_OverwriteRegenerates(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if _, err := GenerateFromSpec(reuseSpec("api"), dir); err != nil {
		t.Fatal(err)
	}
	before := readFiles(t, dir, "root.key", "api.key")

	out, err := GenerateFromSpecWithOptions(reuseSpec("api"), dir, SpecOptions{Overwrite: true})
	if err != nil {
		t.Fatal(err)
	}
	if reused, _ := reusedNames(out); len(reused) != 0 {
		t.Errorf("reused %v with Overwrite, want none", reused)
	}
	after := readFiles(t, dir, "root.key", "api.key")
	for name := range before {
		if bytes.Equal(before[name], after[name]) {
			t.Errorf("%s did not change with Overwrite", name)
		}
	}
}

// Existing files that no longer fit the spec or the hierarchy are reported,
// never silently reused.
func TestGenerateFromSpec_RejectsUnusableFiles(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		breakFiles func(t *testing.T, dir string)
		specs      []CertificateSpec
		want       string
	}{
		{
			name:       "certificate without key",
			breakFiles: func(t *testing.T, dir string) { mustRemove(t, filepath.Join(dir, "api.key")) },
			want:       "exists but its key",
		},
		{
			name:       "key without certificate",
			breakFiles: func(t *testing.T, dir string) { mustRemove(t, filepath.Join(dir, "api.crt")) },
			want:       "exists but its certificate",
		},
		{
			name: "key from another certificate",
			breakFiles: func(t *testing.T, dir string) {
				data := readFiles(t, dir, "root.key")["root.key"]
				if err := os.WriteFile(filepath.Join(dir, "api.key"), data, 0o600); err != nil {
					t.Fatal(err)
				}
			},
			want: "does not match the key in",
		},
		{
			name:  "renamed in the spec",
			specs: []CertificateSpec{{CommonName: "Reuse Root CA", CertificateAuthority: true, KeyType: testSpecECDSA256, Filename: "root", Children: []CertificateSpec{{CommonName: "renamed", KeyType: testSpecECDSA256, Filename: "api"}}}},
			want:  `is for "api", not "renamed"`,
		},
		{
			name:  "no longer a CA",
			specs: []CertificateSpec{{CommonName: "Reuse Root CA", KeyType: testSpecECDSA256, Filename: "root"}},
			want:  "has CA true but the spec has certificateAuthority false",
		},
		{
			name: "parent regenerated",
			breakFiles: func(t *testing.T, dir string) {
				mustRemove(t, filepath.Join(dir, "root.crt"))
				mustRemove(t, filepath.Join(dir, "root.key"))
			},
			want: `is not signed by "Reuse Root CA"`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			if _, err := GenerateFromSpec(reuseSpec("api"), dir); err != nil {
				t.Fatal(err)
			}
			if tc.breakFiles != nil {
				tc.breakFiles(t, dir)
			}
			specs := tc.specs
			if specs == nil {
				specs = reuseSpec("api")
			}
			_, err := GenerateFromSpec(specs, dir)
			if !errors.Is(err, ErrExistingFiles) || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("GenerateFromSpec() err = %v, want ErrExistingFiles containing %q", err, tc.want)
			}
		})
	}
}

func TestGenerateFromSpec_RejectsExpiredFiles(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	specs := []CertificateSpec{{CommonName: "Short", KeyType: testSpecECDSA256, Validity: "1s", Filename: "short"}}
	if _, err := GenerateFromSpec(specs, dir); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond)
	if _, err := GenerateFromSpec(specs, dir); !errors.Is(err, ErrExistingFiles) || !strings.Contains(err.Error(), "expired at") {
		t.Errorf("GenerateFromSpec() err = %v, want an expired error", err)
	}
}

// A reused code signing certificate keeps its .pfx, or gets one rebuilt from
// its key when the .pfx is missing.
func TestGenerateFromSpec_ReusesCodeSigningPFX(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	specs := []CertificateSpec{{CommonName: "Signing", CodeSigning: true, PFXPassword: "pw", Filename: "sign"}}
	if _, err := GenerateFromSpec(specs, dir); err != nil {
		t.Fatal(err)
	}
	before := readFiles(t, dir, "sign.pfx")["sign.pfx"]

	out, err := GenerateFromSpec(specs, dir)
	if err != nil {
		t.Fatal(err)
	}
	if !out[0].Reused || !bytes.Equal(out[0].KeyPair.PFX, before) || !bytes.Equal(readFiles(t, dir, "sign.pfx")["sign.pfx"], before) {
		t.Error("the existing .pfx was not reused as is")
	}

	mustRemove(t, filepath.Join(dir, "sign.pfx"))
	if _, err := GenerateFromSpec(specs, dir); err != nil {
		t.Fatal(err)
	}
	_, cert, err := pkcs12.Decode(readFiles(t, dir, "sign.pfx")["sign.pfx"], "pw")
	if err != nil {
		t.Fatalf("rebuilt .pfx does not decode with the spec's password: %v", err)
	}
	if !cert.Equal(parseCertificatePEM(t, readFiles(t, dir, "sign.crt")["sign.crt"])) {
		t.Error("rebuilt .pfx holds a different certificate")
	}
}

// Top-level certificates signed by an issuer, such as a YubiKey, are only
// reused while they still chain to it.
func TestGenerateFromSpec_ReuseChecksIssuer(t *testing.T) {
	t.Parallel()
	newIssuer := func() *Issuer {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := CreateSelfSignedCertificate(&Args{CA: true, CommonName: "Hardware Root"}, key)
		if err != nil {
			t.Fatal(err)
		}
		return &Issuer{Certificate: cert, Signer: key}
	}
	dir := t.TempDir()
	issuer := newIssuer()
	specs := []CertificateSpec{{CommonName: "Issuing CA", CertificateAuthority: true, KeyType: testSpecECDSA256, Filename: "issuing"}}
	if _, err := GenerateFromSpecWithIssuer(specs, dir, issuer); err != nil {
		t.Fatal(err)
	}
	out, err := GenerateFromSpecWithIssuer(specs, dir, issuer)
	if err != nil || !out[0].Reused {
		t.Fatalf("GenerateFromSpecWithIssuer() again = reused %t, err %v; want the intermediate reused", err == nil && out[0].Reused, err)
	}
	if _, err := GenerateFromSpecWithIssuer(specs, dir, newIssuer()); !errors.Is(err, ErrExistingFiles) {
		t.Errorf("GenerateFromSpecWithIssuer() with another issuer err = %v, want ErrExistingFiles", err)
	}
}

func mustRemove(t *testing.T, path string) {
	t.Helper()

	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
}
