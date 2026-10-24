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
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"path"
	"regexp"
	"slices"
	"strings"
	"text/template"
	"unicode"

	"gopkg.in/yaml.v3"
)

// Scenario names accepted by ScenarioSpec. ScenarioInfos describes each one.
// Each is a template in the scenario directory, named <scenario>.yaml.tmpl.
const (
	ScenarioWeb             = "web"
	ScenarioLocalDev        = "local-dev"
	ScenarioMTLS            = "mtls"
	ScenarioMicroservices   = "microservices"
	ScenarioDatabase        = "database"
	ScenarioActiveDirectory = "active-directory"
	ScenarioKubernetes      = "kubernetes"
	ScenarioVPN             = "vpn"
	ScenarioEAPTLS          = "eap-tls"
	ScenarioIoT             = "iot"
	ScenarioKafka           = "kafka"
	ScenarioDocker          = "docker"
	ScenarioGit             = "git"
	ScenarioSSH             = "ssh"
	ScenarioFTPS            = "ftps"
	ScenarioIOS             = "ios"
	ScenarioAndroid         = "android"
	ScenarioAndroidSigning  = "android-signing"
	ScenarioCodeSign        = "code-sign"
	ScenarioProxy           = "proxy"
)

// scenarioOrder is the order the docs and --scenario help list the
// scenarios in.
var scenarioOrder = []string{
	ScenarioWeb, ScenarioLocalDev, ScenarioMTLS, ScenarioMicroservices, ScenarioDatabase, ScenarioActiveDirectory,
	ScenarioKubernetes, ScenarioVPN, ScenarioEAPTLS, ScenarioIoT, ScenarioKafka, ScenarioDocker, ScenarioGit,
	ScenarioSSH, ScenarioFTPS, ScenarioIOS, ScenarioAndroid, ScenarioAndroidSigning, ScenarioCodeSign, ScenarioProxy,
}

// ScenarioInput says whether a scenario uses one of the ScenarioOptions
// inputs.
type ScenarioInput int

const (
	// InputUnused means the scenario ignores the input.
	InputUnused ScenarioInput = iota
	// InputOptional means the scenario uses the input when it is given.
	InputOptional
	// InputRequired means the scenario needs the input.
	InputRequired
)

// UnmarshalYAML reads "required", "optional", or "unused".
func (in *ScenarioInput) UnmarshalYAML(value *yaml.Node) error {
	switch value.Value {
	case "required":
		*in = InputRequired
	case "optional":
		*in = InputOptional
	case "unused", "":
		*in = InputUnused
	default:
		return fmt.Errorf("input must be required, optional, or unused, not %q", value.Value)
	}
	return nil
}

// ScenarioInfo describes a scenario and the inputs it uses. It is read from
// the comment at the top of the scenario's template.
type ScenarioInfo struct {
	// Name is the scenario's name, such as "web".
	Name string `yaml:"-"`
	// Summary says what the scenario makes, in one sentence.
	Summary string `yaml:"summary"`
	// Hostnames says whether the scenario uses ScenarioOptions.Hostnames,
	// and HostnamesHelp what they are.
	Hostnames     ScenarioInput `yaml:"hostnames"`
	HostnamesHelp string        `yaml:"hostnamesHelp"`
	// Clients says whether the scenario uses ScenarioOptions.Clients, and
	// ClientsHelp what they are.
	Clients     ScenarioInput `yaml:"clients"`
	ClientsHelp string        `yaml:"clientsHelp"`
	// Target is set when the scenario uses ScenarioOptions.Target.
	Target bool `yaml:"target"`
	// SelfSigned is set when the scenario's certificate must be self-signed,
	// so it cannot have an external root.
	SelfSigned bool `yaml:"selfSigned"`
}

//go:embed scenario/*.tmpl
var scenarioFiles embed.FS

// scenarioMetadata is the comment that opens a scenario template and holds
// its ScenarioInfo.
var scenarioMetadata = regexp.MustCompile(`(?s)\A\{\{-?\s*/\*(.*?)\*/\s*-?\}\}`)

// scenarioTemplates holds every scenario template and the helpers they
// share, and scenarioInfos describes the scenarios in scenarioOrder.
var scenarioTemplates, scenarioInfos = mustLoadScenarios()

func mustLoadScenarios() (*template.Template, []ScenarioInfo) {
	tmpl, infos, err := loadScenarios(scenarioFiles)
	if err != nil {
		panic(err)
	}
	return tmpl, infos
}

// loadScenarios parses the templates in fsys and returns them with the
// scenarios they describe, in scenarioOrder.
func loadScenarios(fsys fs.FS) (*template.Template, []ScenarioInfo, error) {
	tmpl := template.New("scenarios").Option("missingkey=error")
	tmpl.Funcs(scenarioFuncs(tmpl))
	files, err := fs.Glob(fsys, "scenario/*.tmpl")
	if err != nil {
		return nil, nil, err
	}
	sources := make(map[string][]byte, len(files))
	for _, file := range files {
		data, err := fs.ReadFile(fsys, file)
		if err != nil {
			return nil, nil, err
		}
		// A Windows checkout may have CRLF line endings, which would end up
		// in the specs.
		data = bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
		if _, err := tmpl.New(path.Base(file)).Parse(string(data)); err != nil {
			return nil, nil, err
		}
		sources[path.Base(file)] = data
	}

	infos := make([]ScenarioInfo, 0, len(scenarioOrder))
	for _, name := range scenarioOrder {
		data, ok := sources[name+".yaml.tmpl"]
		if !ok {
			return nil, nil, fmt.Errorf("scenario %q has no template %s.yaml.tmpl", name, name)
		}
		m := scenarioMetadata.FindSubmatch(data)
		if m == nil {
			return nil, nil, fmt.Errorf("scenario template %s.yaml.tmpl must start with a {{/* ... */}} comment that describes it", name)
		}
		info := ScenarioInfo{Name: name}
		dec := yaml.NewDecoder(bytes.NewReader(m[1]))
		dec.KnownFields(true)
		if err := dec.Decode(&info); err != nil {
			return nil, nil, fmt.Errorf("scenario template %s.yaml.tmpl: %w", name, err)
		}
		if info.Summary == "" {
			return nil, nil, fmt.Errorf("scenario template %s.yaml.tmpl has no summary", name)
		}
		infos = append(infos, info)
	}
	return tmpl, infos, nil
}

// ScenarioInfos returns every scenario, in the order the docs list them.
func ScenarioInfos() []ScenarioInfo {
	return slices.Clone(scenarioInfos)
}

// Scenarios returns the scenario names ScenarioSpec accepts.
func Scenarios() []string {
	return slices.Clone(scenarioOrder)
}

// LookupScenario returns the scenario called name.
func LookupScenario(name string) (ScenarioInfo, bool) {
	for _, info := range scenarioInfos {
		if info.Name == name {
			return info, true
		}
	}
	return ScenarioInfo{}, false
}

// ScenarioOptions are the inputs of ScenarioSpec. The scenario templates see
// them as their data, with the methods below.
type ScenarioOptions struct {
	// Organization is the subject organization of every certificate, and
	// names the CAs. Required.
	Organization string
	// OrganizationalUnit, Country, Locality, and Province are added to every
	// certificate when not empty.
	OrganizationalUnit string
	Country            string
	Locality           string
	Province           string

	// Hostnames are DNS names and IP addresses. What they are depends on the
	// scenario; see ScenarioInfo.HostnamesHelp.
	Hostnames []string
	// Clients are the common names of client certificates. What they are
	// depends on the scenario; see ScenarioInfo.ClientsHelp.
	Clients []string

	// KeyType is the key type of the leaf certificates, such as "ECDSA-256".
	// Empty uses the scenario's default. CAs keep theirs.
	KeyType string
	// Validity is the validity of the leaf certificates, as a Go duration.
	// Empty uses the scenario's default. CAs keep theirs.
	Validity string

	// Target is the code-sign target. Empty uses windows10.
	Target string
	// PFXPasswordEnv is the environment variable every .pfx reads its
	// password from. Required by scenarios that write a .pfx.
	PFXPasswordEnv string

	// ExternalRoot leaves the root CA out, because it lives elsewhere, such
	// as on a YubiKey: the top-level certificates are signed by it.
	ExternalRoot bool

	// SpecPath is the file the spec is written to, which the header's
	// commands name. Empty uses certs.yaml.
	SpecPath string
	// OutputDir is the --output-dir the header's commands name. Empty uses
	// certs.
	OutputDir string
	// Generate says the command that wrote the spec also generated the
	// certificates, as certtool --scenario does without --export-spec.
	Generate bool
}

// KeyTypeOr returns KeyType, or def when it is empty. Templates use it for
// the key type of a leaf certificate.
func (o *ScenarioOptions) KeyTypeOr(def string) string {
	if o.KeyType != "" {
		return o.KeyType
	}
	return def
}

// ValidityOr returns Validity, or def when it is empty. Templates use it for
// the validity of a leaf certificate.
func (o *ScenarioOptions) ValidityOr(def string) string {
	if o.Validity != "" {
		return o.Validity
	}
	return def
}

// RootCert names the certificate of the root CA in file, which clients
// trust; with ExternalRoot it names the YubiKey root's certificate instead.
func (o *ScenarioOptions) RootCert(file string) string {
	if o.ExternalRoot {
		return "the YubiKey root's certificate"
	}
	return file + ".crt"
}

// ScenarioSpec returns a commented YAML spec for the named scenarios, one or
// more of Scenarios. Each scenario adds its own top-level entries, whose file
// names start with the scenario name so scenarios can be combined.
func ScenarioSpec(names []string, opts ScenarioOptions) ([]byte, error) {
	if len(names) == 0 {
		return nil, fmt.Errorf("no scenario given; use one or more of %s", strings.Join(Scenarios(), ", "))
	}
	if opts.Organization == "" {
		return nil, fmt.Errorf("scenarios need an organization to name the certificates")
	}
	if err := checkScenarioText(&opts); err != nil {
		return nil, err
	}
	for _, hostname := range opts.Hostnames {
		if err := ValidateHostname(hostname); err != nil {
			return nil, err
		}
	}

	var body []byte
	seen := map[string]bool{}
	for _, name := range names {
		info, ok := LookupScenario(name)
		if !ok {
			return nil, fmt.Errorf("unknown scenario %q; use one or more of %s", name, strings.Join(Scenarios(), ", "))
		}
		if seen[name] {
			return nil, fmt.Errorf("scenario %q is given twice", name)
		}
		seen[name] = true
		if info.Hostnames == InputRequired && len(opts.Hostnames) == 0 {
			return nil, fmt.Errorf("scenario %q needs hostnames: %s", name, info.HostnamesHelp)
		}
		if info.Clients == InputRequired && len(opts.Clients) == 0 {
			return nil, fmt.Errorf("scenario %q needs clients: %s", name, info.ClientsHelp)
		}
		if info.SelfSigned && opts.ExternalRoot {
			return nil, fmt.Errorf("scenario %q makes a self-signed certificate, so it cannot be signed by an external root such as a YubiKey", name)
		}

		data, err := renderScenario(info, &opts)
		if err != nil {
			return nil, err
		}
		body = append(body, data...)
	}

	data := append(scenarioHeader(names, &opts), body...)
	// Never hand out a spec that certtool would refuse.
	specs, err := UnmarshalSpec(data)
	if err != nil {
		return nil, fmt.Errorf("scenario spec is invalid: %w", err)
	}
	if err := checkScenarioPFX(specs); err != nil {
		return nil, err
	}
	if err := checkScenarioFilenames(specs, map[string]string{}); err != nil {
		return nil, err
	}
	return data, nil
}

// checkScenarioText returns an error when a text input has a control
// character. Templates write the inputs into comments as they are, so a
// newline would end the comment and let the input add its own entries to the
// spec, such as another CA.
func checkScenarioText(o *ScenarioOptions) error {
	fields := []struct {
		name   string
		values []string
	}{
		{"organization", []string{o.Organization}},
		{"organizational unit", []string{o.OrganizationalUnit}},
		{"country", []string{o.Country}},
		{"locality", []string{o.Locality}},
		{"province", []string{o.Province}},
		{"hostname", o.Hostnames},
		{"client", o.Clients},
		{"target", []string{o.Target}},
		{"key type", []string{o.KeyType}},
		{"validity", []string{o.Validity}},
		{"spec path", []string{o.SpecPath}},
		{"output directory", []string{o.OutputDir}},
		{"pfx password environment variable", []string{o.PFXPasswordEnv}},
	}
	for _, f := range fields {
		for _, v := range f.values {
			if HasControlCharacter(v) {
				return fmt.Errorf("the %s %q has a control character, such as a newline, which a scenario cannot write into a spec", f.name, v)
			}
		}
	}
	return nil
}

// HasControlCharacter reports whether s has a control character, such as a
// newline or a tab.
func HasControlCharacter(s string) bool {
	return strings.IndexFunc(s, unicode.IsControl) >= 0
}

// scenarioError is an error a template function returns about the inputs,
// which ScenarioSpec returns without the template's position.
type scenarioError struct{ msg string }

func (e *scenarioError) Error() string { return e.msg }

// renderScenario executes the template of info and returns its entries,
// formatted the way yaml.v3 writes them, with the scenario's summary above
// the first one.
func renderScenario(info ScenarioInfo, opts *ScenarioOptions) ([]byte, error) {
	var out bytes.Buffer
	if err := scenarioTemplates.ExecuteTemplate(&out, info.Name+".yaml.tmpl", opts); err != nil {
		if se, ok := errors.AsType[*scenarioError](err); ok {
			return nil, se
		}
		return nil, fmt.Errorf("scenario %q: %w", info.Name, err)
	}

	var doc yaml.Node
	if err := yaml.Unmarshal(out.Bytes(), &doc); err != nil {
		return nil, fmt.Errorf("scenario %q wrote invalid YAML: %w\n%s", info.Name, err, out.Bytes())
	}
	if len(doc.Content) != 1 || doc.Content[0].Kind != yaml.SequenceNode || len(doc.Content[0].Content) == 0 {
		return nil, fmt.Errorf("scenario %q must write a list of certificates", info.Name)
	}
	first := doc.Content[0].Content[0]
	first.HeadComment = strings.TrimSpace("Scenario " + info.Name + ": " + info.Summary + "\n\n" + first.HeadComment)

	var b bytes.Buffer
	enc := yaml.NewEncoder(&b)
	enc.SetIndent(4)
	if err := enc.Encode(&doc); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// scenarioFuncs are the functions scenario templates can call, besides the
// methods of ScenarioOptions.
func scenarioFuncs(tmpl *template.Template) template.FuncMap {
	return template.FuncMap{
		// yaml writes a string as a YAML scalar, quoted when it needs it.
		"yaml": func(s string) (string, error) {
			data, err := yaml.Marshal(s)
			return strings.TrimSuffix(string(data), "\n"), err
		},
		// include executes a template defined with {{define}} and returns
		// what it wrote, so it can be indented.
		"include": func(name string, data any) (string, error) {
			var b strings.Builder
			err := tmpl.ExecuteTemplate(&b, name, data)
			return b.String(), err
		},
		// nindent starts a new line and indents every line of s by n
		// spaces.
		"nindent": func(n int, s string) string {
			pad := strings.Repeat(" ", n)
			return "\n" + pad + strings.ReplaceAll(s, "\n", "\n"+pad)
		},
		// dict makes a map from key and value pairs, to pass several values
		// to a template.
		"dict": func(pairs ...any) (map[string]any, error) {
			if len(pairs)%2 != 0 {
				return nil, errors.New("dict needs key and value pairs")
			}
			m := make(map[string]any, len(pairs)/2)
			for i := 0; i < len(pairs); i += 2 {
				key, ok := pairs[i].(string)
				if !ok {
					return nil, fmt.Errorf("dict key %v is not a string", pairs[i])
				}
				m[key] = pairs[i+1]
			}
			return m, nil
		},
		// list makes a list of strings.
		"list": func(items ...string) []string { return items },
		// concat joins lists of strings into one.
		"concat": slices.Concat[[]string],
		// host returns a hostname without a port or a trailing dot.
		// trimComment removes the "# " that starts a comment, to continue
		// a comment line with it.
		"trimComment": func(s string) string { return strings.TrimPrefix(s, "# ") },
		"host":        cleanHost,
		"slug":        slugify,
		"isEmail":     func(s string) bool { return ValidateEmailAddress(s) == nil },
		// constraints returns name constraints that permit exactly the given
		// hostnames.
		"constraints": hostnameConstraints,
		// dnsConstraints returns name constraints that permit the given
		// domains.
		"dnsConstraints": func(domains []string) scenarioConstraints { return scenarioConstraints{DNS: domains} },
		// domainOf returns the domain of a domain controller's FQDN.
		"domainOf": func(scenario, hostname string) (string, error) {
			host := cleanHost(hostname)
			_, domain, ok := strings.Cut(strings.ToLower(host), ".")
			if net.ParseIP(host) != nil || !ok || domain == "" {
				return "", &scenarioError{fmt.Sprintf("scenario %q needs the FQDN of each domain controller, such as dc01.corp.example.com, not %q", scenario, hostname)}
			}
			return domain, nil
		},
		// unique returns items without repeats, in order.
		"unique": func(items []string) []string {
			var out []string
			for _, item := range items {
				if !slices.Contains(out, item) {
					out = append(out, item)
				}
			}
			return out
		},
		// codeSignTarget returns the profile of a code-sign target, which
		// defaults to windows10.
		"codeSignTarget": func(target string) (scenarioTarget, error) {
			if target == "" {
				target = windows10Target
			}
			profile, err := GetProfile(target)
			if err != nil {
				return scenarioTarget{}, &scenarioError{err.Error()}
			}
			return scenarioTarget{Name: target, LegacyPFX: profile.LegacyPFX, OutputPFX: profile.OutputPFX}, nil
		},
	}
}

// scenarioTarget is what a template knows about a code-sign target.
type scenarioTarget struct {
	Name      string
	LegacyPFX bool
	OutputPFX bool
}

// scenarioConstraints are the name constraints of a CA in a template.
type scenarioConstraints struct {
	DNS []string
	IP  []string
}

// hostnameConstraints returns name constraints that permit exactly the given
// hostnames: each DNS name and its subdomains, and each IP address.
func hostnameConstraints(hostnames []string) scenarioConstraints {
	var c scenarioConstraints
	for _, hostname := range hostnames {
		host := cleanHost(hostname)
		if ip := net.ParseIP(host); ip != nil {
			bits := 128
			if ip.To4() != nil {
				bits = 32
			}
			if r := fmt.Sprintf("%s/%d", ip, bits); !slices.Contains(c.IP, r) {
				c.IP = append(c.IP, r)
			}
			continue
		}
		if domain := strings.ToLower(strings.TrimPrefix(host, "*.")); !slices.Contains(c.DNS, domain) {
			c.DNS = append(c.DNS, domain)
		}
	}
	return c
}

// cleanHost returns hostname without a port or a trailing dot.
func cleanHost(hostname string) string {
	return strings.TrimSuffix(hostWithoutPort(strings.TrimSpace(hostname)), ".")
}

// checkScenarioPFX returns an error when a spec writes a .pfx without the
// environment variable that holds its password.
func checkScenarioPFX(specs []CertificateSpec) error {
	for i := range specs {
		spec := &specs[i]
		output, _, err := specPFX(spec)
		if err != nil {
			return err
		}
		if output && spec.PFXPasswordEnv == "" {
			return fmt.Errorf("%q writes a .pfx, which needs the environment variable that holds its password", spec.CommonName)
		}
		if err := checkScenarioPFX(spec.Children); err != nil {
			return err
		}
	}
	return nil
}

// checkScenarioFilenames returns an error when two entries would write the
// same files, which happens when hostnames or clients differ only in case or
// punctuation.
func checkScenarioFilenames(specs []CertificateSpec, seen map[string]string) error {
	for _, spec := range specs {
		if other, ok := seen[spec.Filename]; ok {
			return fmt.Errorf("%q and %q would both be written to %s; give them names that differ in more than case or punctuation", other, spec.CommonName, spec.Filename)
		}
		seen[spec.Filename] = spec.CommonName
		if err := checkScenarioFilenames(spec.Children, seen); err != nil {
			return err
		}
	}
	return nil
}

// scenarioHeader is the comment at the top of a scenario spec: the command
// that wrote it, so it can be written again with other inputs, and the one
// that generates its certificates.
func scenarioHeader(names []string, o *ScenarioOptions) []byte {
	path, dir := o.SpecPath, o.OutputDir
	if path == "" {
		path = "certs.yaml"
	}
	if dir == "" {
		dir = "certs"
	}
	made := []string{"certtool", "--scenario", strings.Join(names, ",")}
	flag := func(name, value string) {
		if value != "" {
			made = append(made, "--"+name, shellQuote(value))
		}
	}
	flag("organization", o.Organization)
	flag("organizational-unit", o.OrganizationalUnit)
	flag("country", o.Country)
	flag("locality", o.Locality)
	flag("province", o.Province)
	flag("hostnames", strings.Join(o.Hostnames, ","))
	flag("clients", strings.Join(o.Clients, ","))
	flag("target", o.Target)
	flag("key-type", o.KeyType)
	flag("validity", o.Validity)
	run := "certtool --spec " + shellQuote(path) + " --output-dir " + shellQuote(dir)
	if o.ExternalRoot {
		made = append(made, "--yubikey")
		run = "certtool --yubikey --spec " + shellQuote(path) + " --output-dir " + shellQuote(dir)
	}
	next := "Review it, then generate the certificates with:"
	if o.Generate {
		flag("output-dir", dir)
		next = "which also generated the certificates. To change them, edit this file, then run:"
	} else {
		flag("export-spec", path)
	}

	lines := []string{
		"certtool spec for --scenario " + strings.Join(names, ",") + ", written by:",
		"  " + strings.Join(made, " "),
		next,
		"  " + run,
		"Running it again reuses the certificates already in the output directory,",
		"so you can add entries later. Format: https://github.com/cloudfra/certtool/blob/main/docs/spec.md",
	}
	var b strings.Builder
	for _, l := range lines {
		b.WriteString("# " + l + "\n")
	}
	b.WriteString("\n")
	return []byte(b.String())
}

// shellQuote quotes s for a POSIX shell when it needs it.
func shellQuote(s string) string {
	if s != "" && strings.Trim(s, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._,:/@=+-") == "" {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
