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
	"crypto/x509"
	"flag"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

var updateGolden = flag.Bool("update", false, "rewrite the golden files in testdata")

const scenarioPFXPasswordEnv = "CERTTOOL_TEST_SCENARIO_PFX_PASSWORD" //nolint:gosec // The name of an environment variable, not a credential.

// scenarioCases are the golden scenario specs in testdata/scenarios.
var scenarioCases = []struct {
	name      string
	scenarios []string
	opts      ScenarioOptions
}{
	{
		name:      "web",
		scenarios: []string{ScenarioWeb},
		opts:      ScenarioOptions{Organization: "Acme", Hostnames: []string{"www.example.com", "example.com"}},
	},
	{
		name:      "web-yubikey",
		scenarios: []string{ScenarioWeb},
		opts:      ScenarioOptions{Organization: "Acme", Hostnames: []string{"api.example.com", "10.0.0.12"}, ExternalRoot: true},
	},
	{
		name:      "local-dev",
		scenarios: []string{ScenarioLocalDev},
		opts:      ScenarioOptions{Organization: "Acme", Hostnames: []string{"myapp.localhost"}},
	},
	{
		name:      "mtls",
		scenarios: []string{ScenarioMTLS},
		opts:      ScenarioOptions{Organization: "Acme", Hostnames: []string{"api.internal.example.com"}, Clients: []string{"billing", "Order Service"}, KeyType: "RSA-2048", Validity: "720h"},
	},
	{
		name:      "code-sign",
		scenarios: []string{ScenarioCodeSign},
		opts:      ScenarioOptions{Organization: "Acme", Country: "CA", PFXPasswordEnv: scenarioPFXPasswordEnv},
	},
	{
		name:      "code-sign-windows7",
		scenarios: []string{ScenarioCodeSign},
		opts:      ScenarioOptions{Organization: "Acme", Target: "windows7", PFXPasswordEnv: scenarioPFXPasswordEnv},
	},
	{
		name:      "code-sign-web",
		scenarios: []string{ScenarioCodeSign, ScenarioWeb},
		opts:      ScenarioOptions{Organization: "Acme", Hostnames: []string{"*.example.com"}, Target: "linux"},
	},
}

func TestScenarioSpecGolden(t *testing.T) {
	t.Parallel()
	for _, tc := range scenarioCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := ScenarioSpec(tc.scenarios, tc.opts)
			if err != nil {
				t.Fatalf("ScenarioSpec() err = %v", err)
			}

			path := filepath.Join("testdata", "scenarios", tc.name+".yaml")
			if *updateGolden {
				if err := os.WriteFile(path, got, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(filepath.Clean(path))
			if err != nil {
				t.Fatalf("ReadFile() err = %v; run go test ./pkg/certtool -run TestScenarioSpecGolden -update", err)
			}
			if !bytes.Equal(normalizeNewlines(want), got) {
				t.Errorf("ScenarioSpec() differs from %s; if the change is intended, run go test ./pkg/certtool -run TestScenarioSpecGolden -update\ngot:\n%s", path, got)
			}
		})
	}
}

// TestScenarioSpecGenerates generates the certificates of every scenario and
// checks that the leaves chain to their root.
func TestScenarioSpecGenerates(t *testing.T) {
	t.Setenv(scenarioPFXPasswordEnv, "correct horse battery staple")
	for _, tc := range scenarioCases {
		t.Run(tc.name, func(t *testing.T) {
			data, err := ScenarioSpec(tc.scenarios, tc.opts)
			if err != nil {
				t.Fatalf("ScenarioSpec() err = %v", err)
			}
			specs, err := UnmarshalSpec(data)
			if err != nil {
				t.Fatalf("UnmarshalSpec() err = %v", err)
			}

			var issuer *Issuer
			if tc.opts.ExternalRoot {
				issuer = newTestIssuer(t)
			}
			out, err := GenerateFromSpecWithIssuer(specs, t.TempDir(), issuer)
			if err != nil {
				t.Fatalf("GenerateFromSpecWithIssuer() err = %v", err)
			}

			certs := map[string]*x509.Certificate{}
			for _, o := range out {
				certs[filepath.Base(o.CertPath)] = parseGenCert(t, o)
			}
			for name, cert := range certs {
				if cert.IsCA || bytes.Equal(cert.RawIssuer, cert.RawSubject) {
					continue
				}
				prefix, _, _ := strings.Cut(name, "-")
				root := certs[prefix+"-root-ca.crt"]
				if issuer != nil {
					root = issuer.Certificate
				}
				verifyChain(t, root, cert, certs[prefix+"-issuing-ca.crt"])
			}
		})
	}
}

func TestScenarioSpecNameConstraints(t *testing.T) {
	t.Parallel()
	data, err := ScenarioSpec([]string{ScenarioWeb}, ScenarioOptions{
		Organization: "Acme",
		Hostnames:    []string{"*.Example.com", "example.com.", "api.example.com:443", "10.0.0.1", "10.0.0.1", "2001:db8::1"},
	})
	if err != nil {
		t.Fatalf("ScenarioSpec() err = %v", err)
	}
	specs, err := UnmarshalSpec(data)
	if err != nil {
		t.Fatalf("UnmarshalSpec() err = %v", err)
	}
	root := specs[0]
	if want := []string{"example.com", "api.example.com"}; !slices.Equal(root.PermittedDNSDomains, want) {
		t.Errorf("permittedDNSDomains = %v, want %v", root.PermittedDNSDomains, want)
	}
	if want := []string{"10.0.0.1/32", "2001:db8::1/128"}; !slices.Equal(root.PermittedIPRanges, want) {
		t.Errorf("permittedIPRanges = %v, want %v", root.PermittedIPRanges, want)
	}
}

func TestScenarioSpecErrors(t *testing.T) {
	t.Parallel()
	web := ScenarioOptions{Organization: "Acme", Hostnames: []string{"example.com"}}
	for _, tc := range []struct {
		name      string
		scenarios []string
		opts      ScenarioOptions
		want      string
	}{
		{"none", nil, web, "no scenario"},
		{"unknown", []string{"kubernetes"}, web, `unknown scenario "kubernetes"`},
		{"twice", []string{ScenarioWeb, ScenarioWeb}, web, "given twice"},
		{"no organization", []string{ScenarioLocalDev}, ScenarioOptions{}, "organization"},
		{"web without hostnames", []string{ScenarioWeb}, ScenarioOptions{Organization: "Acme"}, "hostnames"},
		{"mtls without clients", []string{ScenarioMTLS}, web, "client"},
		{"mtls duplicate client", []string{ScenarioMTLS}, ScenarioOptions{Organization: "Acme", Hostnames: []string{"example.com"}, Clients: []string{"a b", "a-b"}}, "given twice"},
		{"bad hostname", []string{ScenarioWeb}, ScenarioOptions{Organization: "Acme", Hostnames: []string{"*.com"}}, "wildcard"},
		{"bad target", []string{ScenarioCodeSign}, ScenarioOptions{Organization: "Acme", Target: "macos", PFXPasswordEnv: "X"}, "unknown target"},
		{"pfx without password env", []string{ScenarioCodeSign}, ScenarioOptions{Organization: "Acme"}, "password"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := ScenarioSpec(tc.scenarios, tc.opts)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("ScenarioSpec() err = %v, want an error containing %q", err, tc.want)
			}
		})
	}
}
