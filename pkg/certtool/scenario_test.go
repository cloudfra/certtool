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
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
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
	newScenarioCase(ScenarioGit, []string{ScenarioGit}, []string{"git.example.com"}, []string{"alice@example.com", "bob@example.com", "ci"}, nil),
	newScenarioCase(ScenarioSSH, []string{ScenarioSSH}, []string{"sftp.example.com", "bastion.example.com"}, []string{"alice", "backup"}, nil),
	newScenarioCase(ScenarioFTPS, []string{ScenarioFTPS}, []string{"ftp.example.com"}, []string{"partner-upload"}, nil),
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
	newScenarioCase("git-server", []string{ScenarioGit}, []string{"git.example.com"}, nil, nil),
	newScenarioCase("git-yubikey", []string{ScenarioGit}, []string{"git.example.com"}, []string{"alice@example.com"}, func(o *ScenarioOptions) { o.ExternalRoot = true }),
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

// TestScenarioSpecExternalRoot renders every scenario that allows it with
// an external root, and checks the certificates chain to it.
func TestScenarioSpecExternalRoot(t *testing.T) {
	t.Setenv(scenarioPFXPasswordEnv, "correct horse battery staple")
	for _, tc := range scenarioCases {
		info, ok := LookupScenario(tc.name)
		if !ok || info.SelfSigned {
			continue
		}
		t.Run(tc.name, func(t *testing.T) {
			opts := tc.opts
			opts.ExternalRoot = true
			data, err := ScenarioSpec(tc.scenarios, opts)
			if err != nil {
				t.Fatalf("ScenarioSpec() err = %v", err)
			}
			specs, err := UnmarshalSpec(data)
			if err != nil {
				t.Fatal(err)
			}
			for _, spec := range specs {
				if spec.CertificateAuthority && strings.HasSuffix(spec.Filename, "root-ca") {
					t.Errorf("the spec has the root CA %q, which is on the YubiKey", spec.CommonName)
				}
			}
			issuer := newTestIssuer(t)
			roots, intermediates := x509.NewCertPool(), x509.NewCertPool()
			roots.AddCert(issuer.Certificate)
			out, err := GenerateFromSpecWithIssuer(specs, t.TempDir(), issuer)
			if err != nil {
				t.Fatalf("GenerateFromSpecWithIssuer() err = %v", err)
			}
			var leaves []*x509.Certificate
			for _, o := range out {
				if cert := parseGenCert(t, o); cert.IsCA {
					intermediates.AddCert(cert)
				} else {
					leaves = append(leaves, cert)
				}
			}
			for _, leaf := range leaves {
				if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
					t.Errorf("certificate %q does not chain to the YubiKey root: %v", leaf.Subject.CommonName, err)
				}
			}
		})
	}
}

// TestScenarioTemplates checks that every scenario has a template and every
// template a scenario.
func TestScenarioTemplates(t *testing.T) {
	t.Parallel()
	files, err := fs.Glob(scenarioFiles, "scenario/*.yaml.tmpl")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if name := strings.TrimSuffix(path.Base(f), ".yaml.tmpl"); !slices.Contains(Scenarios(), name) {
			t.Errorf("%s is not in scenarioOrder, so --scenario cannot use it", f)
		}
	}
	if len(files) != len(Scenarios()) {
		t.Errorf("%d templates for %d scenarios", len(files), len(Scenarios()))
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
		{"ssh without clients", []string{ScenarioSSH}, web, "needs clients"},
		{"duplicate git person", []string{ScenarioGit}, with(func(o *ScenarioOptions) { o.Clients = []string{"a@example.com", "A@example.com"} }), "would both be written"},
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
	return strings.Join(append(args, "--output-dir", "certs"), " ")
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
		"`certtool --scenario` writes a commented spec for a common situation to `--output-dir` and generates the certificates in it. The comments in the spec say what every certificate is for and how to install it. To change the certificates, edit the spec and run it with `--spec`.\n\n" +
		"```bash\n" +
		"certtool --scenario web --organization Acme --organizational-unit Platform --hostnames www.example.com,example.com --output-dir certs\n" +
		"# After editing certs/web.yaml:\n" +
		"certtool --spec certs/web.yaml --output-dir certs\n" +
		"```\n\n" +
		"- Running the same `--scenario` command again reuses the spec and the certificates. If the spec was edited, it stops and says to use `--spec` instead, so edits are never lost; `--overwrite` replaces the spec and every certificate.\n" +
		"- `--export-spec certs.yaml` only writes the spec, and `--export-spec -` writes it to standard output.\n" +
		"- Separate scenarios with commas, such as `--scenario web,code-sign`. Each adds its own top-level entries, and every file name starts with the scenario name, so they can share an output directory. The `kubernetes` scenario is the exception: it uses kubeadm's file names.\n" +
		"- The subject flags (`--organization`, `--country`, and so on), `--key-type`, and `--validity` set the leaf certificates. CAs keep their own key types and validities. A flag that none of the chosen scenarios uses is an error.\n" +
		"- With `--yubikey`, the root CA is left out because it is on the YubiKey: the CAs below it become top-level entries, which the YubiKey signs.\n" +
		"- Each scenario is a template in [pkg/certtool/scenario](../pkg/certtool/scenario), whose data is the flags above.\n" +
		"- Every `.pfx` reads its password from the `CERTTOOL_PFX_PASSWORD` environment variable when the spec is generated. The spec never holds a password.\n" +
		"- Running the spec again reuses the certificates already in the output directory, so you can add entries later. See [Running a spec again](spec.md#running-a-spec-again).\n\n" +
		"| Scenario | Makes |\n" +
		"| -------- | ----- |\n")
	for _, info := range ScenarioInfos() {
		fmt.Fprintf(&b, "| [`%s`](#%s) | %s |\n", info.Name, info.Name, info.Summary)
	}
	b.WriteString("\nOther systems fit one of these: `web` for OpenLDAP, mail servers, and Elasticsearch over HTTPS; `git` for Subversion and Mercurial over HTTPS; `ssh` for SFTP-only accounts and rsync backups; `mtls` for gRPC; `microservices` for a service mesh without its own CA.\n")

	for _, info := range ScenarioInfos() {
		i := slices.IndexFunc(scenarioCases, func(c scenarioCase) bool { return c.name == info.Name })
		if i < 0 {
			return nil, fmt.Errorf("scenario %q has no example", info.Name)
		}
		tc := scenarioCases[i]
		// Show the spec as the one-command form writes it.
		opts := tc.opts
		opts.SpecPath, opts.OutputDir, opts.Generate = "certs/"+strings.Join(tc.scenarios, "+")+".yaml", "certs", true
		spec, err := ScenarioSpec(tc.scenarios, opts)
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

		run := scenarioCommand(tc)
		if bytes.Contains(spec, []byte("pfxPasswordEnv")) {
			run = "# CERTTOOL_PFX_PASSWORD must hold the password for the .pfx files\n" + run
		}
		fmt.Fprintf(&b, "```bash\n%s\n```\n\nIt writes certs/%s.yaml and generates the certificates in it:\n\n```yaml\n%s```\n", run, strings.Join(tc.scenarios, "+"), spec)
	}
	return []byte(b.String()), nil
}

// TestScenarioGitIdentities checks that a person's certificate signs email
// under a CA gpgsm accepts, and that people and machines get SSH keys.
func TestScenarioGitIdentities(t *testing.T) {
	t.Setenv(scenarioPFXPasswordEnv, "correct horse battery staple")
	opts := ScenarioOptions{Organization: "Acme", Hostnames: []string{"git.example.com"}, Clients: []string{"alice@example.com", "ci"}, PFXPasswordEnv: scenarioPFXPasswordEnv}
	data, err := ScenarioSpec([]string{ScenarioGit}, opts)
	if err != nil {
		t.Fatal(err)
	}
	specs, err := UnmarshalSpec(data)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	out, err := GenerateFromSpec(specs, dir)
	if err != nil {
		t.Fatal(err)
	}
	certs := map[string]*x509.Certificate{}
	for _, o := range out {
		certs[o.CommonName] = parseGenCert(t, o)
	}

	identityCA := certs["Acme Git Identity CA"]
	if identityCA == nil || len(identityCA.PermittedDNSDomains) > 0 || !slices.Contains(identityCA.ExtKeyUsage, x509.ExtKeyUsageEmailProtection) {
		t.Fatalf("identity CA = %+v, want one without name constraints that allows email protection", identityCA)
	}
	alice := certs["alice@example.com"]
	if !slices.Equal(alice.EmailAddresses, []string{"alice@example.com"}) || len(alice.DNSNames) > 0 || len(alice.IPAddresses) > 0 {
		t.Errorf("alice's names = %v %v %v, want only the email address", alice.EmailAddresses, alice.DNSNames, alice.IPAddresses)
	}
	roots := x509.NewCertPool()
	roots.AddCert(identityCA)
	if _, err := alice.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection}}); err != nil {
		t.Errorf("alice's certificate is not valid for email protection: %v", err)
	}
	if ci := certs["ci"]; len(ci.EmailAddresses) > 0 {
		t.Errorf("machine certificate has email addresses %v", ci.EmailAddresses)
	}
	for _, name := range []string{"git-person-alice-example-com", "git-machine-ci"} {
		if _, err := os.Stat(filepath.Join(dir, name+".key.pub")); err != nil {
			t.Errorf("no SSH public key for %s: %v", name, err)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "git-person-alice-example-com.pfx")); err != nil {
		t.Errorf("no .pfx for gpgsm: %v", err)
	}
}

func TestScenarioSpecHeader(t *testing.T) {
	t.Parallel()
	opts := ScenarioOptions{Organization: "Acme Corp", Hostnames: []string{"a.example.com"}, KeyType: "RSA-2048", ExternalRoot: true, SpecPath: "my specs/web.yaml"}
	data, err := ScenarioSpec([]string{ScenarioWeb}, opts)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"#   certtool --scenario web --organization 'Acme Corp' --hostnames a.example.com --key-type RSA-2048 --yubikey --export-spec 'my specs/web.yaml'\n",
		"#   certtool --yubikey --spec 'my specs/web.yaml' --output-dir certs\n",
	} {
		if !strings.Contains(string(data), want) {
			t.Errorf("header does not contain %q:\n%s", want, data)
		}
	}
}

// TestLoadScenariosCRLF checks that templates checked out with Windows line
// endings write the same specs.
func TestLoadScenariosCRLF(t *testing.T) {
	t.Parallel()
	crlf := fstest.MapFS{}
	files, err := fs.Glob(scenarioFiles, "scenario/*.tmpl")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		data, err := fs.ReadFile(scenarioFiles, f)
		if err != nil {
			t.Fatal(err)
		}
		// A Windows checkout already has CRLF line endings.
		data = bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
		crlf[f] = &fstest.MapFile{Data: bytes.ReplaceAll(data, []byte("\n"), []byte("\r\n"))}
	}
	tmpl, _, err := loadScenarios(crlf)
	if err != nil {
		t.Fatal(err)
	}
	var got bytes.Buffer
	opts := &ScenarioOptions{Organization: "Acme", Hostnames: []string{"example.com"}}
	if err := tmpl.ExecuteTemplate(&got, "web.yaml.tmpl", opts); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(got.Bytes(), []byte("\r")) {
		t.Errorf("a template with CRLF line endings wrote a carriage return:\n%q", got.String())
	}
}
