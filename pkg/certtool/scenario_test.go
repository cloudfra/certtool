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
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

var updateGolden = flag.Bool("update", false, "rewrite the golden files in testdata and docs/scenarios.md")

// scenarioPFXPasswordEnv is the variable the CLI passes as PFXPasswordEnv.
const scenarioPFXPasswordEnv = "CERTTOOL_PFX_PASSWORD" //nolint:gosec // The name of an environment variable, not a credential.

type scenarioCase struct {
	// name is the golden file's name. Cases named after a scenario are the
	// examples in docs/scenarios.md.
	name      string
	scenarios []string
	opts      ScenarioOptions
}

func newScenarioCase(name string, scenarios []string, hostnames, clients []string, edit func(*ScenarioOptions)) scenarioCase {
	opts := ScenarioOptions{Organization: "Acme", Hostnames: hostnames, Clients: clients, PFXPasswordEnv: scenarioPFXPasswordEnv}
	if edit != nil {
		edit(&opts)
	}
	return scenarioCase{name: name, scenarios: scenarios, opts: opts}
}

// scenarioCases has an example of every scenario, then variants.
var scenarioCases = []scenarioCase{
	newScenarioCase(ScenarioWeb, []string{ScenarioWeb}, []string{"www.example.com", "example.com"}, nil, nil),
	newScenarioCase(ScenarioLocalDev, []string{ScenarioLocalDev}, []string{"myapp.localhost"}, nil, nil),
	newScenarioCase(ScenarioMTLS, []string{ScenarioMTLS}, []string{"api.internal.example.com"}, []string{"billing", "orders"}, nil),
	newScenarioCase(ScenarioMicroservices, []string{ScenarioMicroservices}, []string{"api.platform.svc.cluster.local", "orders.platform.svc.cluster.local", "payments.platform.svc.cluster.local"}, nil, nil),
	newScenarioCase(ScenarioDatabase, []string{ScenarioDatabase}, []string{"postgres.internal.example.com", "redis.internal.example.com"}, []string{"app"}, nil),
	newScenarioCase(ScenarioActiveDirectory, []string{ScenarioActiveDirectory}, []string{"dc01.corp.example.com", "dc02.corp.example.com"}, nil, nil),
	newScenarioCase(ScenarioKubernetes, []string{ScenarioKubernetes}, []string{"cp1", "192.168.1.100", "k8s-api.example.com"}, nil, nil),
	newScenarioCase(ScenarioVPN, []string{ScenarioVPN}, []string{"vpn.example.com", "203.0.113.10"}, []string{"alice", "bob"}, nil),
	newScenarioCase(ScenarioEAPTLS, []string{ScenarioEAPTLS}, []string{"radius.corp.example.com"}, []string{"alice-laptop", "bob-phone"}, nil),
	newScenarioCase(ScenarioIoT, []string{ScenarioIoT}, []string{"mqtt.example.com"}, []string{"sensor-0001", "sensor-0002"}, nil),
	newScenarioCase(ScenarioKafka, []string{ScenarioKafka}, []string{"kafka-1.example.com", "kafka-2.example.com", "kafka-3.example.com"}, []string{"orders-service"}, nil),
	newScenarioCase(ScenarioDocker, []string{ScenarioDocker}, []string{"docker-host.example.com", "192.168.1.50"}, nil, nil),
	newScenarioCase(ScenarioIOS, []string{ScenarioIOS}, []string{"api.dev.example.com"}, []string{"test-device"}, nil),
	newScenarioCase(ScenarioAndroid, []string{ScenarioAndroid}, []string{"api.dev.example.com", "10.0.2.2"}, []string{"test-device"}, nil),
	newScenarioCase(ScenarioAndroidSigning, []string{ScenarioAndroidSigning}, nil, nil, nil),
	newScenarioCase(ScenarioCodeSign, []string{ScenarioCodeSign}, nil, nil, nil),
	newScenarioCase(ScenarioProxy, []string{ScenarioProxy}, nil, nil, nil),

	newScenarioCase("web-yubikey", []string{ScenarioWeb}, []string{"api.example.com", "10.0.0.12"}, nil, func(o *ScenarioOptions) { o.ExternalRoot = true }),
	newScenarioCase("database-yubikey", []string{ScenarioDatabase}, []string{"postgres.internal.example.com"}, nil, func(o *ScenarioOptions) { o.ExternalRoot = true }),
	newScenarioCase("kubernetes-yubikey", []string{ScenarioKubernetes}, []string{"cp1"}, nil, func(o *ScenarioOptions) { o.ExternalRoot = true }),
	newScenarioCase("mtls-rsa", []string{ScenarioMTLS}, []string{"api.internal.example.com"}, []string{"Order Service"}, func(o *ScenarioOptions) {
		o.KeyType, o.Validity, o.Country = "RSA-2048", "720h", "CA"
	}),
	newScenarioCase("code-sign-windows7", []string{ScenarioCodeSign}, nil, nil, func(o *ScenarioOptions) { o.Target = "windows7" }),
	newScenarioCase("code-sign-web", []string{ScenarioCodeSign, ScenarioWeb}, []string{"*.example.com"}, nil, func(o *ScenarioOptions) { o.Target = "linux" }),
}

func TestScenarioCasesCoverEveryScenario(t *testing.T) {
	t.Parallel()
	for _, name := range Scenarios() {
		if !slices.ContainsFunc(scenarioCases, func(c scenarioCase) bool { return c.name == name }) {
			t.Errorf("scenario %q has no case in scenarioCases, so it has no golden file or example in docs/scenarios.md", name)
		}
	}
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
				t.Fatalf("ReadFile() err = %v; run go test ./pkg/certtool -run TestScenario -update", err)
			}
			if !bytes.Equal(normalizeNewlines(want), got) {
				t.Errorf("ScenarioSpec() differs from %s; if the change is intended, run go test ./pkg/certtool -run TestScenario -update\ngot:\n%s", path, got)
			}
		})
	}
}

// TestScenarioSpecGenerates generates the certificates of every case and
// checks that each leaf chains to a root through the CAs, which also checks
// the name constraints.
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

			roots, intermediates := x509.NewCertPool(), x509.NewCertPool()
			var issuer *Issuer
			if tc.opts.ExternalRoot {
				issuer = newTestIssuer(t)
				roots.AddCert(issuer.Certificate)
			}
			out, err := GenerateFromSpecWithIssuer(specs, t.TempDir(), issuer)
			if err != nil {
				t.Fatalf("GenerateFromSpecWithIssuer() err = %v", err)
			}

			var leaves []*x509.Certificate
			for _, o := range out {
				cert := parseGenCert(t, o)
				selfSigned := bytes.Equal(cert.RawIssuer, cert.RawSubject)
				switch {
				case cert.IsCA && selfSigned:
					roots.AddCert(cert)
				case cert.IsCA:
					intermediates.AddCert(cert)
				case !selfSigned:
					leaves = append(leaves, cert)
				}
			}
			for _, leaf := range leaves {
				opts := x509.VerifyOptions{Roots: roots, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}
				if _, err := leaf.Verify(opts); err != nil {
					t.Errorf("certificate %q does not chain to a root: %v", leaf.Subject.CommonName, err)
				}
			}
		})
	}
}

// TestScenarioSpecPFX checks that the scenarios that promise a .pfx write
// one.
func TestScenarioSpecPFX(t *testing.T) {
	t.Setenv(scenarioPFXPasswordEnv, "correct horse battery staple")
	for _, tc := range []struct {
		scenario string
		want     []string
	}{
		{ScenarioActiveDirectory, []string{"active-directory-dc01-corp-example-com.pfx", "active-directory-dc02-corp-example-com.pfx"}},
		{ScenarioKafka, []string{"kafka-kafka-1-example-com.pfx", "kafka-client-orders-service.pfx"}},
		{ScenarioVPN, []string{"vpn-client-alice.pfx"}},
		{ScenarioEAPTLS, []string{"eap-tls-radius.pfx", "eap-tls-client-bob-phone.pfx"}},
		{ScenarioIOS, []string{"ios-client-test-device.pfx"}},
		{ScenarioAndroid, []string{"android-client-test-device.pfx"}},
		{ScenarioAndroidSigning, []string{"android-signing.pfx"}},
		{ScenarioCodeSign, []string{"code-sign.pfx"}},
	} {
		t.Run(tc.scenario, func(t *testing.T) {
			i := slices.IndexFunc(scenarioCases, func(c scenarioCase) bool { return c.name == tc.scenario })
			data, err := ScenarioSpec(scenarioCases[i].scenarios, scenarioCases[i].opts)
			if err != nil {
				t.Fatalf("ScenarioSpec() err = %v", err)
			}
			specs, err := UnmarshalSpec(data)
			if err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			if _, err := GenerateFromSpec(specs, dir); err != nil {
				t.Fatalf("GenerateFromSpec() err = %v", err)
			}
			for _, name := range tc.want {
				if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
					t.Errorf("%s was not written: %v", name, err)
				}
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
	web := ScenarioOptions{Organization: "Acme", Hostnames: []string{"example.com"}, PFXPasswordEnv: "X"}
	with := func(edit func(*ScenarioOptions)) ScenarioOptions {
		o := web
		edit(&o)
		return o
	}
	for _, tc := range []struct {
		name      string
		scenarios []string
		opts      ScenarioOptions
		want      string
	}{
		{"none", nil, web, "no scenario"},
		{"unknown", []string{"nomad"}, web, `unknown scenario "nomad"`},
		{"twice", []string{ScenarioWeb, ScenarioWeb}, web, "given twice"},
		{"no organization", []string{ScenarioLocalDev}, ScenarioOptions{}, "organization"},
		{"web without hostnames", []string{ScenarioWeb}, with(func(o *ScenarioOptions) { o.Hostnames = nil }), "needs hostnames"},
		{"mtls without clients", []string{ScenarioMTLS}, web, "needs clients"},
		{"duplicate client", []string{ScenarioMTLS}, with(func(o *ScenarioOptions) { o.Clients = []string{"a b", "A-B"} }), "would both be written"},
		{"duplicate service", []string{ScenarioMicroservices}, with(func(o *ScenarioOptions) { o.Hostnames = []string{"a.example.com", "A.example.com"} }), "would both be written"},
		{"bad hostname", []string{ScenarioWeb}, with(func(o *ScenarioOptions) { o.Hostnames = []string{"*.com"} }), "wildcard"},
		{"domain controller without domain", []string{ScenarioActiveDirectory}, with(func(o *ScenarioOptions) { o.Hostnames = []string{"dc01"} }), "FQDN"},
		{"domain controller address", []string{ScenarioActiveDirectory}, with(func(o *ScenarioOptions) { o.Hostnames = []string{"10.0.0.1"} }), "FQDN"},
		{"bad target", []string{ScenarioCodeSign}, with(func(o *ScenarioOptions) { o.Target = "macos" }), "unknown target"},
		{"pfx without password env", []string{ScenarioActiveDirectory}, with(func(o *ScenarioOptions) { o.Hostnames = []string{"dc01.corp.example.com"}; o.PFXPasswordEnv = "" }), "password"},
		{"android signing on a YubiKey", []string{ScenarioAndroidSigning}, with(func(o *ScenarioOptions) { o.ExternalRoot = true }), "self-signed"},
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

// TestScenarioDocs keeps docs/scenarios.md identical to what scenarioDocs
// generates from the scenarios and their examples.
func TestScenarioDocs(t *testing.T) {
	t.Parallel()
	got, err := scenarioDocs()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join("..", "..", "docs", "scenarios.md")
	if *updateGolden {
		if err := os.WriteFile(path, got, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(normalizeNewlines(want), got) {
		t.Errorf("docs/scenarios.md is out of date; run go test ./pkg/certtool -run TestScenario -update")
	}
}

// scenarioCommand returns the certtool command line of a case.
func scenarioCommand(tc scenarioCase) string {
	args := []string{"certtool", "--scenario", strings.Join(tc.scenarios, ","), "--organization", tc.opts.Organization}
	if len(tc.opts.Hostnames) > 0 {
		args = append(args, "--hostnames", strings.Join(tc.opts.Hostnames, ","))
	}
	if len(tc.opts.Clients) > 0 {
		args = append(args, "--clients", strings.Join(tc.opts.Clients, ","))
	}
	if tc.opts.Target != "" {
		args = append(args, "--target", tc.opts.Target)
	}
	if tc.opts.ExternalRoot {
		args = append(args, "--yubikey")
	}
	return strings.Join(append(args, "--export-spec", "certs.yaml"), " ")
}

func describeInput(input ScenarioInput, help string) string {
	switch input {
	case InputRequired:
		return help
	case InputOptional:
		return "optional, " + help
	}
	return ""
}

// scenarioDocs generates docs/scenarios.md.
func scenarioDocs() ([]byte, error) {
	var b strings.Builder
	b.WriteString("# Scenarios\n\n" +
		"<!-- Generated by TestScenarioDocs in pkg/certtool/scenario_test.go: run go test ./pkg/certtool -run TestScenario -update. -->\n\n" +
		"`certtool --scenario` writes a commented spec for a common situation. Review it, change what you need, then generate the certificates with `--spec`. The comments in each spec say what every certificate is for and how to install it.\n\n" +
		"```bash\n" +
		"certtool --scenario web --organization Acme --hostnames www.example.com,example.com --export-spec certs.yaml\n" +
		"certtool --spec certs.yaml --output-dir certs\n" +
		"```\n\n" +
		"- `--export-spec -` writes the spec to standard output.\n" +
		"- Separate scenarios with commas, such as `--scenario web,code-sign`. Each adds its own top-level entries, and every file name starts with the scenario name, so they can share an output directory. The `kubernetes` scenario is the exception: it uses kubeadm's file names.\n" +
		"- The subject flags (`--organization`, `--country`, and so on), `--key-type`, and `--validity` set the leaf certificates. CAs keep their own key types and validities. A flag that none of the chosen scenarios uses is an error.\n" +
		"- With `--yubikey`, the root CA is left out because it is on the YubiKey: the CAs below it become top-level entries, which `certtool --yubikey --spec` signs with the YubiKey.\n" +
		"- Every `.pfx` reads its password from the `CERTTOOL_PFX_PASSWORD` environment variable when the spec is generated. The spec never holds a password.\n" +
		"- Running the spec again reuses the certificates already in the output directory, so you can add entries later. See [Running a spec again](spec.md#running-a-spec-again).\n\n" +
		"| Scenario | Makes |\n" +
		"| -------- | ----- |\n")
	for _, info := range ScenarioInfos() {
		fmt.Fprintf(&b, "| [`%s`](#%s) | %s |\n", info.Name, info.Name, info.Summary)
	}
	b.WriteString("\nOther systems fit one of these: `web` for OpenLDAP, mail servers, and Elasticsearch over HTTPS; `mtls` for gRPC; `microservices` for a service mesh without its own CA.\n")

	for _, info := range ScenarioInfos() {
		i := slices.IndexFunc(scenarioCases, func(c scenarioCase) bool { return c.name == info.Name })
		if i < 0 {
			return nil, fmt.Errorf("scenario %q has no example", info.Name)
		}
		tc := scenarioCases[i]
		spec, err := ScenarioSpec(tc.scenarios, tc.opts)
		if err != nil {
			return nil, err
		}

		fmt.Fprintf(&b, "\n## %s\n\n%s\n\n", info.Name, info.Summary)
		var inputs []string
		if h := describeInput(info.Hostnames, info.HostnamesHelp); h != "" {
			inputs = append(inputs, "- `--hostnames`: "+h+".")
		}
		if c := describeInput(info.Clients, info.ClientsHelp); c != "" {
			inputs = append(inputs, "- `--clients`: "+c+".")
		}
		if info.Target {
			inputs = append(inputs, "- `--target`: `windows10` (the default), `windows11`, `windows7`, or `linux`.")
		}
		if info.SelfSigned {
			inputs = append(inputs, "- Always self-signed, so it cannot be combined with `--yubikey`.")
		}
		if len(inputs) > 0 {
			b.WriteString(strings.Join(inputs, "\n") + "\n\n")
		}

		run := "certtool --spec certs.yaml --output-dir certs"
		if bytes.Contains(spec, []byte("pfxPasswordEnv")) {
			run = "# CERTTOOL_PFX_PASSWORD must hold the password for the .pfx files\n" + run
		}
		fmt.Fprintf(&b, "```bash\n%s\n%s\n```\n\n```yaml\n%s```\n", scenarioCommand(tc), run, spec)
	}
	return []byte(b.String()), nil
}
