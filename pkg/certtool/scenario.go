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
	"fmt"
	"net"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

// Scenario names accepted by ScenarioSpec. ScenarioInfos describes each one.
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
	ScenarioIOS             = "ios"
	ScenarioAndroid         = "android"
	ScenarioAndroidSigning  = "android-signing"
	ScenarioCodeSign        = "code-sign"
	ScenarioProxy           = "proxy"
)

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

// ScenarioInfo describes a scenario and the inputs it uses.
type ScenarioInfo struct {
	// Name is the scenario's name, such as "web".
	Name string
	// Summary says what the scenario makes, in one sentence.
	Summary string
	// Hostnames says whether the scenario uses ScenarioOptions.Hostnames,
	// and HostnamesHelp what they are.
	Hostnames     ScenarioInput
	HostnamesHelp string
	// Clients says whether the scenario uses ScenarioOptions.Clients, and
	// ClientsHelp what they are.
	Clients     ScenarioInput
	ClientsHelp string
	// Target is set when the scenario uses ScenarioOptions.Target.
	Target bool
	// SelfSigned is set when the scenario's certificate must be self-signed,
	// so it cannot have an external root.
	SelfSigned bool

	build func(*ScenarioOptions) ([]scenarioEntry, error)
}

var scenarioInfos = []ScenarioInfo{
	{
		Name:          ScenarioWeb,
		Summary:       "A root CA and an issuing CA, name constrained to the hostnames, and a server certificate for websites and APIs.",
		Hostnames:     InputRequired,
		HostnamesHelp: "the names of the server certificate, which also become the CA's name constraints",
		build:         webScenario,
	},
	{
		Name:          ScenarioLocalDev,
		Summary:       "A self-signed certificate for localhost and development hostnames.",
		Hostnames:     InputOptional,
		HostnamesHelp: "development names to add to localhost, such as myapp.localhost",
		build:         localDevScenario,
	},
	{
		Name:          ScenarioMTLS,
		Summary:       "A root CA and an issuing CA that sign a server certificate and client certificates for mutual TLS, such as gRPC.",
		Hostnames:     InputRequired,
		HostnamesHelp: "the names of the server certificate",
		Clients:       InputRequired,
		ClientsHelp:   "the names of the client certificates, such as billing,orders",
		build:         mtlsScenario,
	},
	{
		Name:          ScenarioMicroservices,
		Summary:       "A root CA and an issuing CA that sign one certificate per service, used both to serve and to call the other services.",
		Hostnames:     InputRequired,
		HostnamesHelp: "the DNS name of each service, one certificate each, such as api.platform.svc.cluster.local",
		build:         microservicesScenario,
	},
	{
		Name:          ScenarioDatabase,
		Summary:       "A CA that signs a server certificate per database host and client certificates for database users (PostgreSQL, MySQL, Redis, MongoDB).",
		Hostnames:     InputRequired,
		HostnamesHelp: "the name of each database server, one certificate each",
		Clients:       InputOptional,
		ClientsHelp:   "database users that log in with a certificate",
		build:         databaseScenario,
	},
	{
		Name:          ScenarioActiveDirectory,
		Summary:       "An enterprise root CA and issuing CA that sign LDAPS certificates for Active Directory domain controllers, with .pfx files to import.",
		Hostnames:     InputRequired,
		HostnamesHelp: "the FQDN of each domain controller, such as dc01.corp.example.com",
		build:         activeDirectoryScenario,
	},
	{
		Name:          ScenarioKubernetes,
		Summary:       "The certificates kubeadm puts in /etc/kubernetes/pki: the cluster, front proxy, and etcd CAs and the certificates they sign.",
		Hostnames:     InputRequired,
		HostnamesHelp: "the control-plane node name first, then its IP addresses and any load balancer name",
		build:         kubernetesScenario,
	},
	{
		Name:          ScenarioVPN,
		Summary:       "A CA that signs a VPN gateway certificate and client certificates, for OpenVPN and IKEv2/IPsec (strongSwan, Windows, macOS, iOS, Android).",
		Hostnames:     InputRequired,
		HostnamesHelp: "the names and addresses clients connect to the gateway by",
		Clients:       InputRequired,
		ClientsHelp:   "the users or devices that connect, one certificate each",
		build:         vpnScenario,
	},
	{
		Name:          ScenarioEAPTLS,
		Summary:       "A CA that signs a RADIUS server certificate and client certificates for 802.1X EAP-TLS on Wi-Fi and wired networks.",
		Hostnames:     InputRequired,
		HostnamesHelp: "the name of the RADIUS server, which supplicants check",
		Clients:       InputRequired,
		ClientsHelp:   "the users or devices that join the network, one certificate each",
		build:         eapTLSScenario,
	},
	{
		Name:          ScenarioIoT,
		Summary:       "A root CA and a device CA that sign an MQTT broker certificate and long-lived device certificates.",
		Hostnames:     InputRequired,
		HostnamesHelp: "the names of the MQTT broker",
		Clients:       InputRequired,
		ClientsHelp:   "the device IDs, one certificate each",
		build:         iotScenario,
	},
	{
		Name:          ScenarioKafka,
		Summary:       "A CA that signs a certificate per Kafka broker, with PKCS#12 keystores, and client certificates.",
		Hostnames:     InputRequired,
		HostnamesHelp: "the name of each broker, one certificate each",
		Clients:       InputOptional,
		ClientsHelp:   "the Kafka clients that authenticate with a certificate",
		build:         kafkaScenario,
	},
	{
		Name:          ScenarioDocker,
		Summary:       "A CA that signs a Docker daemon certificate and client certificates, to protect the Docker API on port 2376.",
		Hostnames:     InputRequired,
		HostnamesHelp: "the names and addresses of the Docker host",
		Clients:       InputOptional,
		ClientsHelp:   "the clients that may use the Docker API; one named docker-client when not given",
		build:         dockerScenario,
	},
	{
		Name:          ScenarioIOS,
		Summary:       "A development CA for iPhone and iPad apps, a backend certificate that meets Apple's TLS rules, and client identities.",
		Hostnames:     InputRequired,
		HostnamesHelp: "the names of the backend the app connects to",
		Clients:       InputOptional,
		ClientsHelp:   "client identities for apps that use mutual TLS",
		build:         iosScenario,
	},
	{
		Name:          ScenarioAndroid,
		Summary:       "A development CA that Android apps trust through a network security config, a backend certificate, and client certificates.",
		Hostnames:     InputRequired,
		HostnamesHelp: "the names of the backend the app connects to; add 10.0.2.2 to reach the host from the emulator",
		Clients:       InputOptional,
		ClientsHelp:   "client certificates for apps that use mutual TLS",
		build:         androidScenario,
	},
	{
		Name:       ScenarioAndroidSigning,
		Summary:    "An Android app signing (upload) key in a PKCS#12 keystore, valid for 25 years.",
		SelfSigned: true,
		build:      androidSigningScenario,
	},
	{
		Name:    ScenarioCodeSign,
		Summary: "A code signing certificate for Windows (signtool) or Linux (osslsigncode).",
		Target:  true,
		build:   codeSignScenario,
	},
	{
		Name:    ScenarioProxy,
		Summary: "A CA for a TLS-inspecting proxy (Squid, mitmproxy), which signs a certificate for each site on the fly.",
		build:   proxyScenario,
	},
}

// ScenarioInfos returns every scenario, in the order the docs list them.
func ScenarioInfos() []ScenarioInfo {
	return slices.Clone(scenarioInfos)
}

// Scenarios returns the scenario names ScenarioSpec accepts.
func Scenarios() []string {
	names := make([]string, len(scenarioInfos))
	for i, info := range scenarioInfos {
		names[i] = info.Name
	}
	return names
}

// LookupScenario returns the scenario called name.
func LookupScenario(name string) (ScenarioInfo, bool) {
	i := slices.IndexFunc(scenarioInfos, func(info ScenarioInfo) bool { return info.Name == name })
	if i < 0 {
		return ScenarioInfo{}, false
	}
	return scenarioInfos[i], true
}

// Default key types and validities of the certificates scenarios make.
const (
	scenarioRootKeyType    = "ECDSA-384"
	scenarioIssuingKeyType = "ECDSA-256"
	scenarioLeafKeyType    = "ECDSA-256"
	scenarioRSAKeyType     = "RSA-2048"
	scenarioRSACAKeyType   = "RSA-4096"

	validity25Years = "219000h"
	validity10Years = "87600h"
	validity5Years  = "43800h"
	validity3Years  = "26280h"
	validity1Year   = "8760h"
	validity397Days = "9528h"
	validity180Days = "4380h"
	validity90Days  = "2160h"
)

// ScenarioOptions are the inputs of ScenarioSpec.
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
}

// scenarioEntry is a certificate spec with the comments written next to it.
type scenarioEntry struct {
	spec CertificateSpec
	// comment is written above the entry.
	comment string
	// fieldComments are written above the field with the given YAML key.
	fieldComments map[string]string
	children      []scenarioEntry
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

	var entries []scenarioEntry
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

		added, err := info.build(&opts)
		if err != nil {
			return nil, err
		}
		added[0].comment = "Scenario " + name + ": " + info.Summary + "\n\n" + added[0].comment
		entries = append(entries, added...)
	}

	if err := setPFXPasswordEnv(entries, opts.PFXPasswordEnv); err != nil {
		return nil, err
	}
	if err := checkScenarioFilenames(entries, map[string]string{}); err != nil {
		return nil, err
	}
	data, err := marshalScenario(entries)
	if err != nil {
		return nil, err
	}
	// Never hand out a spec that certtool would refuse.
	if _, err := UnmarshalSpec(data); err != nil {
		return nil, fmt.Errorf("scenario spec is invalid: %w", err)
	}
	return data, nil
}

// setPFXPasswordEnv makes every entry that writes a .pfx read its password
// from env.
func setPFXPasswordEnv(entries []scenarioEntry, env string) error {
	for i := range entries {
		spec := &entries[i].spec
		output, _, err := specPFX(spec)
		if err != nil {
			return err
		}
		if output {
			if env == "" {
				return fmt.Errorf("%q writes a .pfx, which needs the environment variable that holds its password", spec.CommonName)
			}
			spec.PFXPasswordEnv = env
		}
		if err := setPFXPasswordEnv(entries[i].children, env); err != nil {
			return err
		}
	}
	return nil
}

// checkScenarioFilenames returns an error when two entries would write the
// same files, which happens when hostnames or clients differ only in case or
// punctuation.
func checkScenarioFilenames(entries []scenarioEntry, seen map[string]string) error {
	for _, e := range entries {
		if other, ok := seen[e.spec.Filename]; ok {
			return fmt.Errorf("%q and %q would both be written to %s; give them names that differ in more than case or punctuation", other, e.spec.CommonName, e.spec.Filename)
		}
		seen[e.spec.Filename] = e.spec.CommonName
		if err := checkScenarioFilenames(e.children, seen); err != nil {
			return err
		}
	}
	return nil
}

// subject returns a spec with the subject fields of o.
func (o *ScenarioOptions) subject(commonName, filename string) CertificateSpec {
	return CertificateSpec{
		CommonName:         commonName,
		Organization:       o.Organization,
		OrganizationalUnit: o.OrganizationalUnit,
		Country:            o.Country,
		Locality:           o.Locality,
		Province:           o.Province,
		Filename:           filename,
	}
}

// leaf returns a leaf certificate spec with the given key type and validity,
// unless KeyType or Validity override them.
func (o *ScenarioOptions) leaf(commonName, filename, keyType, validity string) CertificateSpec {
	spec := o.subject(commonName, filename)
	spec.KeyType = keyType
	if o.KeyType != "" {
		spec.KeyType = o.KeyType
	}
	spec.Validity = validity
	if o.Validity != "" {
		spec.Validity = o.Validity
	}
	return spec
}

// caPlan describes the CAs of a scenario.
type caPlan struct {
	scenario string
	// label names the CAs: "<organization> <label> Root CA".
	label string
	// twoTier adds an issuing CA below the root, so the root key can be
	// kept offline.
	twoTier bool
	// rootKeyType and issuingKeyType default to ECDSA-384 and ECDSA-256.
	rootKeyType    string
	issuingKeyType string
	// constrain name constrains the top CA to the hostnames, or to
	// dnsDomains when set.
	constrain  bool
	dnsDomains []string
	// trust says how to make the other side trust the root.
	trust string
}

// rootFile is the file name of the top CA in the spec.
func (p *caPlan) rootFile() string {
	if p.twoTier {
		return p.scenario + "-root-ca"
	}
	return p.scenario + "-ca"
}

// issuerFile is the file name of the CA that signs the leaves.
func (p *caPlan) issuerFile() string {
	if p.twoTier {
		return p.scenario + "-issuing-ca"
	}
	return p.scenario + "-ca"
}

// chainNote says which certificates a leaf presents, when the other side
// trusts only the root.
func (p *caPlan) chainNote(o *ScenarioOptions, filename string) string {
	if !p.twoTier && !o.ExternalRoot {
		return ""
	}
	return "\nPresent " + filename + ".crt followed by " + p.issuerFile() + ".crt, so the other side only needs to trust the root."
}

// hierarchy returns the CAs of p with leaves below the CA that signs them.
func (p *caPlan) hierarchy(o *ScenarioOptions, leaves []scenarioEntry) ([]scenarioEntry, error) {
	var dnsDomains, ipRanges []string
	if p.constrain {
		dnsDomains = p.dnsDomains
		if dnsDomains == nil {
			var err error
			if dnsDomains, ipRanges, err = hostnameConstraints(o.Hostnames); err != nil {
				return nil, err
			}
		}
	}
	rootKeyType, issuingKeyType := p.rootKeyType, p.issuingKeyType
	if rootKeyType == "" {
		rootKeyType = scenarioRootKeyType
	}
	if issuingKeyType == "" {
		issuingKeyType = scenarioIssuingKeyType
	}
	yubiKeyNote := "Signed by the root CA on the YubiKey: run this spec with certtool --yubikey --spec.\n"

	// top is the CA at the top of the spec, which carries the name
	// constraints and the instructions for trusting the hierarchy.
	var top scenarioEntry
	switch {
	case p.twoTier:
		spec := o.subject(o.Organization+" "+p.label+" Issuing CA", p.issuerFile())
		spec.CertificateAuthority = true
		spec.KeyType = issuingKeyType
		spec.Validity = validity3Years
		issuing := scenarioEntry{
			spec:          spec,
			comment:       "Issuing CA: signs the day-to-day certificates. Renew it well before it expires, because a certificate is only valid\nwhile its issuers are.",
			fieldComments: map[string]string{"validity": "3 years."},
			children:      leaves,
		}
		if o.ExternalRoot {
			top = issuing
			top.comment = yubiKeyNote + p.trust + "\n" + top.comment
			break
		}

		spec = o.subject(o.Organization+" "+p.label+" Root CA", p.rootFile())
		spec.CertificateAuthority = true
		spec.KeyType = rootKeyType
		spec.Validity = validity10Years
		top = scenarioEntry{
			spec:          spec,
			comment:       "Root CA. " + p.trust + "\nIts key can sign anything below it, so move " + p.rootFile() + ".key offline once the issuing CA exists,\nor keep the root on a YubiKey: certtool --scenario " + p.scenario + " --yubikey.",
			fieldComments: map[string]string{"validity": "10 years."},
			children:      []scenarioEntry{issuing},
		}
	default:
		spec := o.subject(o.Organization+" "+p.label+" CA", p.rootFile())
		spec.CertificateAuthority = true
		spec.KeyType = rootKeyType
		spec.Validity = validity10Years
		top = scenarioEntry{
			spec:          spec,
			comment:       "CA. " + p.trust + "\nIts key signs every certificate below it: keep " + p.rootFile() + ".key off the servers, and use it only to issue certificates.",
			fieldComments: map[string]string{"validity": "10 years."},
			children:      leaves,
		}
		if o.ExternalRoot {
			top.spec.Validity = validity3Years
			top.fieldComments["validity"] = "3 years."
			top.comment = yubiKeyNote + top.comment
		}
	}

	if p.constrain {
		top.spec.PermittedDNSDomains = dnsDomains
		top.spec.PermittedIPRanges = ipRanges
		top.fieldComments["permittedDNSDomains"] = "Name constraints: certificates below this CA may only use these names and their subdomains.\nAdd a domain before you issue a certificate for it; changing them later means regenerating the CA and everything below it."
		if len(ipRanges) == 0 {
			top.fieldComments["permittedDNSDomains"] += "\nIP addresses are not limited, so certtool still adds 127.0.0.1; add permittedIPRanges to limit them."
		}
		top.fieldComments["permittedIPRanges"] = "The IP addresses certificates below this CA may use."
	}
	return []scenarioEntry{top}, nil
}

// hostnameConstraints returns name constraints that permit exactly the given
// hostnames: each DNS name and its subdomains, and each IP address.
func hostnameConstraints(hostnames []string) (dnsDomains, ipRanges []string, err error) {
	for _, hostname := range hostnames {
		if err := ValidateHostname(hostname); err != nil {
			return nil, nil, err
		}
		host := cleanHost(hostname)
		if ip := net.ParseIP(host); ip != nil {
			bits := 128
			if ip.To4() != nil {
				bits = 32
			}
			if r := fmt.Sprintf("%s/%d", ip, bits); !slices.Contains(ipRanges, r) {
				ipRanges = append(ipRanges, r)
			}
			continue
		}
		if domain := strings.ToLower(strings.TrimPrefix(host, "*.")); !slices.Contains(dnsDomains, domain) {
			dnsDomains = append(dnsDomains, domain)
		}
	}
	return dnsDomains, ipRanges, nil
}

// cleanHost returns hostname without a port or a trailing dot.
func cleanHost(hostname string) string {
	return strings.TrimSuffix(hostWithoutPort(strings.TrimSpace(hostname)), ".")
}

// server returns one certificate for all the hostnames.
func (o *ScenarioOptions) server(filename, keyType, validity, comment string) scenarioEntry {
	spec := o.leaf(cleanHost(o.Hostnames[0]), filename, keyType, validity)
	spec.Hostnames = slices.Clone(o.Hostnames)
	return scenarioEntry{
		spec:          spec,
		comment:       comment,
		fieldComments: map[string]string{"validity": renewComment(filename)},
	}
}

// serverPerHost returns a certificate for each hostname. comment describes
// the certificate of host written to filename.
func (o *ScenarioOptions) serverPerHost(scenario, keyType, validity string, comment func(host, filename string) string) []scenarioEntry {
	entries := make([]scenarioEntry, 0, len(o.Hostnames))
	for _, hostname := range o.Hostnames {
		host := cleanHost(hostname)
		filename := scenario + "-" + slugify(host)
		spec := o.leaf(host, filename, keyType, validity)
		spec.Hostnames = []string{hostname}
		entries = append(entries, scenarioEntry{
			spec:          spec,
			comment:       comment(host, filename),
			fieldComments: map[string]string{"validity": renewComment(filename)},
		})
	}
	return entries
}

// clients returns a certificate for each client, written to
// "<scenario>-<kind>-<name>". pfx is the .pfx format, or empty for none.
func (o *ScenarioOptions) clients(names []string, scenario, kind, keyType, validity, pfx string, comment func(name, filename string) string) []scenarioEntry {
	entries := make([]scenarioEntry, 0, len(names))
	for _, name := range names {
		filename := scenario + "-" + kind + "-" + slugify(name)
		spec := o.leaf(name, filename, keyType, validity)
		spec.PFX = pfx
		entries = append(entries, scenarioEntry{spec: spec, comment: comment(name, filename)})
	}
	return entries
}

func renewComment(filename string) string {
	return "To renew, delete " + filename + ".crt and " + filename + ".key, then run the spec again."
}

func webScenario(o *ScenarioOptions) ([]scenarioEntry, error) {
	plan := &caPlan{
		scenario:  ScenarioWeb,
		label:     "Web",
		twoTier:   true,
		constrain: true,
		trust:     "Install " + ScenarioWeb + "-root-ca.crt in the trust store of every client: the operating system, the browser, or the HTTP client's CA bundle.",
	}
	server := o.server(ScenarioWeb+"-server", scenarioLeafKeyType, validity90Days,
		"Server certificate for the hostnames, valid for 90 days. nginx: ssl_certificate takes "+ScenarioWeb+"-server.crt followed by\n"+
			plan.issuerFile()+".crt in one file, and ssl_certificate_key takes "+ScenarioWeb+"-server.key.\n"+
			"To add a server, copy this entry with a new commonName, hostnames, and filename.")
	return plan.hierarchy(o, []scenarioEntry{server})
}

func localDevScenario(o *ScenarioOptions) ([]scenarioEntry, error) {
	commonName := "localhost"
	if len(o.Hostnames) > 0 {
		commonName = cleanHost(o.Hostnames[0])
	}
	spec := o.leaf(commonName, ScenarioLocalDev, scenarioLeafKeyType, validity1Year)
	spec.Hostnames = append(slices.Clone(o.Hostnames), "::1")

	comment := "Self-signed certificate for this machine. certtool adds localhost and 127.0.0.1 itself.\nTrust " + ScenarioLocalDev + ".crt only on the machine that holds " + ScenarioLocalDev + ".key; see docs/use-cases/local-development.md."
	if o.ExternalRoot {
		comment = "Certificate for this machine, signed by the root CA on the YubiKey: run this spec with certtool --yubikey --spec.\ncerttool adds localhost and 127.0.0.1 itself. Machines that trust the YubiKey root trust it."
	}
	return []scenarioEntry{{
		spec:          spec,
		comment:       comment,
		fieldComments: map[string]string{"hostnames": "Add the names you browse to, such as myapp.localhost."},
	}}, nil
}

func mtlsScenario(o *ScenarioOptions) ([]scenarioEntry, error) {
	plan := &caPlan{
		scenario:  ScenarioMTLS,
		label:     "mTLS",
		twoTier:   true,
		constrain: true,
		trust:     "Both sides trust " + ScenarioMTLS + "-root-ca.crt: the server to verify clients, and the clients to verify the server.",
	}
	server := o.server(ScenarioMTLS+"-server", scenarioLeafKeyType, validity90Days,
		"Server certificate. Require a client certificate that chains to the root: nginx ssl_verify_client on with\n"+
			"ssl_client_certificate "+plan.rootFile()+".crt, or in Go tls.RequireAndVerifyClientCert with the root in ClientCAs."+plan.chainNote(o, ScenarioMTLS+"-server"))
	clients := o.clients(o.Clients, ScenarioMTLS, "client", scenarioLeafKeyType, validity90Days, "", func(name, filename string) string {
		return "Client certificate for " + name + ", valid for 90 days. The server sees " + name + " as the subject common name:\n" +
			"authorize on it, not just on the CA. To use it from a browser, add pfx: modern." + plan.chainNote(o, filename)
	})
	return plan.hierarchy(o, append([]scenarioEntry{server}, clients...))
}

func microservicesScenario(o *ScenarioOptions) ([]scenarioEntry, error) {
	plan := &caPlan{
		scenario:  ScenarioMicroservices,
		label:     "Services",
		twoTier:   true,
		constrain: true,
		trust:     "Every service trusts " + ScenarioMicroservices + "-root-ca.crt to verify its peers, and requires a client certificate from them.",
	}
	leaves := o.serverPerHost(ScenarioMicroservices, scenarioLeafKeyType, validity90Days, func(host, filename string) string {
		return "Certificate for the service " + host + ". The service serves with it and presents it when it calls other services,\n" +
			"because certtool's TLS certificates are valid for both. Authorize callers by name, not just by the CA." + plan.chainNote(o, filename)
	})
	return plan.hierarchy(o, leaves)
}

func databaseScenario(o *ScenarioOptions) ([]scenarioEntry, error) {
	plan := &caPlan{
		scenario:  ScenarioDatabase,
		label:     "Database",
		constrain: true,
		trust: "Clients verify the servers with " + ScenarioDatabase + "-ca.crt: PostgreSQL sslrootcert with sslmode=verify-full, MySQL ssl-ca\n" +
			"with ssl-mode=VERIFY_IDENTITY, Redis tls-ca-cert-file, MongoDB tlsCAFile.",
	}
	leaves := o.serverPerHost(ScenarioDatabase, scenarioLeafKeyType, validity1Year, func(host, filename string) string {
		return "Server certificate for " + host + ". PostgreSQL: ssl_cert_file and ssl_key_file (the key must belong to the postgres user).\n" +
			"MySQL: ssl_cert and ssl_key. Redis: tls-cert-file and tls-key-file. MongoDB: tlsCertificateKeyFile takes the\n" +
			"certificate and key in one file: cat " + filename + ".crt " + filename + ".key > " + filename + ".pem."
	})
	users := o.clients(o.Clients, ScenarioDatabase, "user", scenarioLeafKeyType, validity1Year, "", func(name, _ string) string {
		return "Client certificate for the database user " + name + ", whose user name is the common name. PostgreSQL logs it in with\n" +
			"the cert method in pg_hba.conf (hostssl all " + name + " all cert); MySQL with CREATE USER ... REQUIRE SUBJECT."
	})
	return plan.hierarchy(o, append(leaves, users...))
}

func activeDirectoryScenario(o *ScenarioOptions) ([]scenarioEntry, error) {
	var domains []string
	for _, hostname := range o.Hostnames {
		host := cleanHost(hostname)
		_, domain, ok := strings.Cut(strings.ToLower(host), ".")
		if net.ParseIP(host) != nil || !ok || domain == "" {
			return nil, fmt.Errorf("scenario %q needs the FQDN of each domain controller, such as dc01.corp.example.com, not %q", ScenarioActiveDirectory, hostname)
		}
		if !slices.Contains(domains, domain) {
			domains = append(domains, domain)
		}
	}
	plan := &caPlan{
		scenario:       ScenarioActiveDirectory,
		label:          "Enterprise",
		twoTier:        true,
		rootKeyType:    scenarioRSACAKeyType,
		issuingKeyType: scenarioRSACAKeyType,
		constrain:      true,
		dnsDomains:     domains,
		trust: "Publish " + ScenarioActiveDirectory + "-root-ca.crt to every domain member with Group Policy (Computer Configuration > Policies >\n" +
			"Windows Settings > Security Settings > Public Key Policies > Trusted Root Certification Authorities), or with\n" +
			"certutil -dspublish -f " + ScenarioActiveDirectory + "-root-ca.crt RootCA, and the issuing CA with\n" +
			"certutil -dspublish -f " + ScenarioActiveDirectory + "-issuing-ca.crt SubCA. RSA keys, because some LDAP clients do not accept ECDSA.",
	}
	leaves := make([]scenarioEntry, 0, len(o.Hostnames))
	for _, hostname := range o.Hostnames {
		host := cleanHost(hostname)
		_, domain, _ := strings.Cut(strings.ToLower(host), ".")
		filename := ScenarioActiveDirectory + "-" + slugify(host)
		spec := o.leaf(host, filename, scenarioRSAKeyType, validity1Year)
		spec.Hostnames = []string{host, domain}
		spec.PFX = PFXModern
		leaves = append(leaves, scenarioEntry{
			spec: spec,
			comment: "LDAPS certificate for the domain controller " + host + ". On it, in an administrator PowerShell:\n" +
				"  Import-PfxCertificate -FilePath " + filename + ".pfx -CertStoreLocation Cert:\\LocalMachine\\My `\n" +
				"    -Password (ConvertTo-SecureString $env:CERTTOOL_PFX_PASSWORD -AsPlainText -Force)\n" +
				"The DC uses it for LDAPS on port 636, and 3269 for the global catalog, within minutes or after a restart.\n" +
				"Check with: openssl s_client -connect " + host + ":636 -CAfile " + plan.rootFile() + ".crt",
			fieldComments: map[string]string{
				"hostnames": "The DC's name, and the domain name, so clients that connect to " + domain + " reach any DC.",
				"validity":  renewComment(filename) + "\nThen import the new .pfx and delete the old certificate from the store.",
			},
		})
	}
	return plan.hierarchy(o, leaves)
}

func kubernetesScenario(o *ScenarioOptions) ([]scenarioEntry, error) {
	nodeName := cleanHost(o.Hostnames[0])
	k8s := func(commonName, filename string) CertificateSpec {
		return o.leaf(commonName, filename, scenarioRSAKeyType, validity1Year)
	}
	ca := func(commonName, filename string) CertificateSpec {
		spec := o.subject(commonName, filename)
		spec.CertificateAuthority = true
		spec.KeyType = scenarioRSAKeyType
		spec.Validity = validity10Years
		if o.ExternalRoot {
			spec.Validity = validity3Years
		}
		return spec
	}
	signedBy := ""
	if o.ExternalRoot {
		signedBy = "\nSigned by the root CA on the YubiKey: run this spec with certtool --yubikey --spec. Kubernetes components trust\nthe CA file directly, so they do not need the YubiKey root."
	}

	apiserver := k8s("kube-apiserver", "apiserver")
	apiserver.Hostnames = append(slices.Clone(o.Hostnames), "kubernetes", "kubernetes.default", "kubernetes.default.svc", "kubernetes.default.svc.cluster.local", "10.96.0.1")
	kubeletClient := k8s("kube-apiserver-kubelet-client", "apiserver-kubelet-client")
	kubeletClient.Organization = "system:masters"
	etcdServer := k8s(nodeName, "etcd-server")
	etcdServer.Hostnames = append(slices.Clone(o.Hostnames), "::1")
	etcdPeer := k8s(nodeName, "etcd-peer")
	etcdPeer.Hostnames = slices.Clone(o.Hostnames)

	return []scenarioEntry{
		{
			spec: ca("kubernetes", "ca"),
			comment: "Cluster CA. The file names are kubeadm's: generate with --output-dir /etc/kubernetes/pki on the first control-plane\n" +
				"node, move the etcd files as the etcd CA says, then run kubeadm init. kubeadm uses these certificates and makes\n" +
				"the kubeconfig files, the service account key pair (sa.key, sa.pub), and anything else that is missing.\n" +
				"Kubernetes reads a client certificate's organization as a group, so do not bind RBAC roles to " + o.Organization + "." + signedBy,
			children: []scenarioEntry{
				{
					spec:    apiserver,
					comment: "API server certificate.",
					fieldComments: map[string]string{
						"hostnames": "Every name and address clients use for the API server: the node, a load balancer, and the first address of\n" +
							"the service CIDR (10.96.0.1 for kubeadm's default 10.96.0.0/12). Change cluster.local if the cluster domain differs.",
					},
				},
				{
					spec:          kubeletClient,
					comment:       "The client certificate the API server presents to kubelets.",
					fieldComments: map[string]string{"organization": "A Kubernetes group: system:masters may always use the kubelet API."},
				},
			},
		},
		{
			spec: ca("front-proxy-ca", "front-proxy-ca"),
			comment: "Front proxy CA for the aggregation layer (--requestheader-client-ca-file). kubeadm keeps it separate from the\n" +
				"cluster CA, so a front proxy certificate cannot be used as a user's client certificate." + signedBy,
			children: []scenarioEntry{{spec: k8s("front-proxy-client", "front-proxy-client"), comment: "The client certificate the API server presents to extension API servers."}},
		},
		{
			spec: ca("etcd-ca", "etcd-ca"),
			comment: "etcd CA. kubeadm reads the etcd certificates from /etc/kubernetes/pki/etcd/: move etcd-ca, etcd-server, etcd-peer,\n" +
				"and etcd-healthcheck-client (.crt and .key) there as ca, server, peer, and healthcheck-client." + signedBy,
			children: []scenarioEntry{
				{spec: etcdServer, comment: "etcd server certificate, named after the node."},
				{spec: etcdPeer, comment: "etcd peer certificate, for the other members of the etcd cluster. Its hostnames are the node's addresses."},
				{spec: k8s("kube-etcd-healthcheck-client", "etcd-healthcheck-client"), comment: "Client certificate for the etcd liveness probe."},
				{spec: k8s("kube-apiserver-etcd-client", "apiserver-etcd-client"), comment: "The client certificate the API server presents to etcd. It stays in /etc/kubernetes/pki."},
			},
		},
	}, nil
}

func vpnScenario(o *ScenarioOptions) ([]scenarioEntry, error) {
	plan := &caPlan{
		scenario:  ScenarioVPN,
		label:     "VPN",
		constrain: true,
		trust: "Gateways and clients trust " + ScenarioVPN + "-ca.crt (OpenVPN: ca; strongSwan: /etc/swanctl/x509ca).\n" +
			"certtool does not make CRLs, so keep client certificates short-lived; OpenVPN needs a CRL to revoke one early.",
	}
	gateway := o.server(ScenarioVPN+"-gateway", scenarioLeafKeyType, validity1Year,
		"Gateway certificate. OpenVPN: cert "+ScenarioVPN+"-gateway.crt and key "+ScenarioVPN+"-gateway.key. strongSwan: /etc/swanctl/x509 and private.\n"+
			"IKEv2 clients on Windows, macOS, iOS, and Android check that the name they connect to is in hostnames.\n"+
			"To add a gateway, copy this entry with a new commonName, hostnames, and filename.")
	clients := o.clients(o.Clients, ScenarioVPN, "client", scenarioLeafKeyType, validity180Days, PFXModern, func(name, filename string) string {
		return "Client certificate for " + name + ", valid for 180 days. OpenVPN clients use the .crt and .key; Windows, macOS, iOS, and\n" +
			"Android import " + filename + ".pfx. Every certtool TLS certificate is also valid for server authentication, so make\n" +
			"OpenVPN clients check the gateway's name with verify-x509-name " + cleanHost(o.Hostnames[0]) + " name, not only remote-cert-tls server."
	})
	return plan.hierarchy(o, append([]scenarioEntry{gateway}, clients...))
}

func eapTLSScenario(o *ScenarioOptions) ([]scenarioEntry, error) {
	plan := &caPlan{
		scenario:  ScenarioEAPTLS,
		label:     "Network Access",
		constrain: true,
		trust: "Configure every supplicant to trust only " + ScenarioEAPTLS + "-ca.crt for this network and to check the RADIUS server's name;\n" +
			"otherwise anyone with a certificate from another CA the device trusts could pose as the network.",
	}
	radius := o.server(ScenarioEAPTLS+"-radius", scenarioLeafKeyType, validity1Year,
		"RADIUS server certificate. FreeRADIUS: certificate_file, private_key_file, and ca_file in mods-available/eap.\n"+
			"Windows NPS: import "+ScenarioEAPTLS+"-radius.pfx into the computer's Personal store and choose it in the network policy.")
	radius.spec.PFX = PFXModern
	clients := o.clients(o.Clients, ScenarioEAPTLS, "client", scenarioLeafKeyType, validity1Year, PFXModern, func(name, filename string) string {
		return "Client certificate for " + name + ". Windows, macOS, iOS, and Android import " + filename + ".pfx, or an MDM pushes it\n" +
			"with the Wi-Fi profile. Linux wpa_supplicant uses client_cert and private_key. RADIUS can authorize on the common name."
	})
	return plan.hierarchy(o, append([]scenarioEntry{radius}, clients...))
}

func iotScenario(o *ScenarioOptions) ([]scenarioEntry, error) {
	plan := &caPlan{
		scenario:  ScenarioIoT,
		label:     "Device",
		twoTier:   true,
		constrain: true,
		trust:     "The broker trusts " + ScenarioIoT + "-root-ca.crt to verify devices, and every device carries it to verify the broker.",
	}
	broker := o.server(ScenarioIoT+"-broker", scenarioLeafKeyType, validity1Year,
		"MQTT broker certificate. In the broker's configuration: cafile "+plan.rootFile()+".crt, certfile (this certificate followed by "+plan.issuerFile()+".crt),\n"+
			"keyfile, require_certificate true, and use_identity_as_username true, which makes each device's common name its user.")
	devices := o.clients(o.Clients, ScenarioIoT, "device", scenarioLeafKeyType, validity5Years, "", func(name, filename string) string {
		return "Device certificate for " + name + ". Provision the device with " + filename + ".crt, " + filename + ".key, " + plan.issuerFile() + ".crt,\n" +
			"and " + plan.rootFile() + ".crt. Valid for 5 years, because devices are hard to reach; plan how to replace it before then."
	})
	return plan.hierarchy(o, append([]scenarioEntry{broker}, devices...))
}

func kafkaScenario(o *ScenarioOptions) ([]scenarioEntry, error) {
	plan := &caPlan{
		scenario:  ScenarioKafka,
		label:     "Kafka",
		constrain: true,
		trust:     "Brokers and clients trust " + ScenarioKafka + "-ca.crt: ssl.truststore.type=PEM and ssl.truststore.location=" + ScenarioKafka + "-ca.crt.",
	}
	brokers := o.serverPerHost(ScenarioKafka, scenarioLeafKeyType, validity1Year, func(host, filename string) string {
		return "Broker certificate for " + host + ". In server.properties: ssl.keystore.type=PKCS12, ssl.keystore.location=" + filename + ".pfx,\n" +
			"ssl.keystore.password and ssl.key.password set to the .pfx password, and ssl.client.auth=required for mutual TLS."
	})
	for i := range brokers {
		brokers[i].spec.PFX = PFXModern
	}
	clients := o.clients(o.Clients, ScenarioKafka, "client", scenarioLeafKeyType, validity1Year, PFXModern, func(name, filename string) string {
		return "Client certificate for " + name + ", in " + filename + ".pfx for the client's ssl.keystore.location. Kafka's principal is the\n" +
			"whole subject (User:CN=" + name + ",O=...); to use the common name in ACLs, set\n" +
			"ssl.principal.mapping.rules=RULE:^CN=([^,]+).*$/$1/,DEFAULT on the brokers."
	})
	return plan.hierarchy(o, append(brokers, clients...))
}

func dockerScenario(o *ScenarioOptions) ([]scenarioEntry, error) {
	plan := &caPlan{
		scenario:  ScenarioDocker,
		label:     "Docker",
		constrain: true,
		trust:     "The daemon trusts " + ScenarioDocker + "-ca.crt to verify clients, and clients trust it to verify the daemon.",
	}
	daemon := o.server(ScenarioDocker+"-daemon", scenarioLeafKeyType, validity1Year,
		"Docker daemon certificate. dockerd --tlsverify --tlscacert="+ScenarioDocker+"-ca.crt --tlscert="+ScenarioDocker+"-daemon.crt\n"+
			"--tlskey="+ScenarioDocker+"-daemon.key -H=0.0.0.0:2376, or the same settings in /etc/docker/daemon.json.")
	names := o.Clients
	if len(names) == 0 {
		names = []string{"docker-client"}
	}
	clients := o.clients(names, ScenarioDocker, "client", scenarioLeafKeyType, validity1Year, "", func(name, filename string) string {
		return "Client certificate for " + name + ". Anyone who has it controls the Docker host. Copy " + ScenarioDocker + "-ca.crt, " + filename + ".crt,\n" +
			"and " + filename + ".key to ~/.docker as ca.pem, cert.pem, and key.pem, then run: docker --tlsverify -H=" + cleanHost(o.Hostnames[0]) + ":2376 version"
	})
	return plan.hierarchy(o, append([]scenarioEntry{daemon}, clients...))
}

func iosScenario(o *ScenarioOptions) ([]scenarioEntry, error) {
	plan := &caPlan{
		scenario:  ScenarioIOS,
		label:     "iOS Development",
		constrain: true,
		trust: "On a device, AirDrop or email " + ScenarioIOS + "-ca.crt, install the profile in Settings, then turn on full trust in\n" +
			"Settings > General > About > Certificate Trust Settings. In the Simulator: xcrun simctl keychain booted add-root-cert " + ScenarioIOS + "-ca.crt.\n" +
			"App Transport Security then accepts the backend without exceptions. Apps themselves are signed with certificates from Apple.",
	}
	server := o.server(ScenarioIOS+"-server", scenarioLeafKeyType, validity397Days,
		"Backend certificate. Apple platforms reject TLS server certificates that are valid for more than 825 days, lack the\n"+
			"name in hostnames, or have RSA keys under 2048 bits; this one is valid for 397 days.")
	clients := o.clients(o.Clients, ScenarioIOS, "client", scenarioLeafKeyType, validity1Year, PFXLegacy, func(name, filename string) string {
		return "Client identity for " + name + ". The app loads " + filename + ".pfx with SecPKCS12Import, or a configuration profile installs it.\n" +
			"The .pfx uses the legacy format, which older iOS and macOS releases need to import it; give it a long random password."
	})
	return plan.hierarchy(o, append([]scenarioEntry{server}, clients...))
}

func androidScenario(o *ScenarioOptions) ([]scenarioEntry, error) {
	plan := &caPlan{
		scenario:  ScenarioAndroid,
		label:     "Android Development",
		constrain: true,
		trust: "Android apps do not trust user-installed CAs. Copy " + ScenarioAndroid + "-ca.crt to res/raw/android_ca.crt (resource names\n" +
			"cannot contain hyphens) and trust it in res/xml/network_security_config.xml, inside <debug-overrides> to keep it\n" +
			"out of release builds: <trust-anchors><certificates src=\"@raw/android_ca\"/></trust-anchors>.",
	}
	server := o.server(ScenarioAndroid+"-server", scenarioLeafKeyType, validity1Year,
		"Backend certificate. The emulator reaches the host machine at 10.0.2.2: pass it in --hostnames to use this from the emulator.")
	clients := o.clients(o.Clients, ScenarioAndroid, "client", scenarioLeafKeyType, validity1Year, PFXModern, func(name, filename string) string {
		return "Client certificate for " + name + ". Load " + filename + ".pfx into a KeyStore of type PKCS12 for the app's SSLContext or\n" +
			"OkHttp client, or install it in Settings > Security > Encryption & credentials for the browser."
	})
	return plan.hierarchy(o, append([]scenarioEntry{server}, clients...))
}

func androidSigningScenario(o *ScenarioOptions) ([]scenarioEntry, error) {
	spec := o.subject(o.Organization+" Android Upload Key", ScenarioAndroidSigning)
	spec.CodeSigning = true
	spec.Target = androidTarget
	spec.KeyType = o.KeyType
	spec.Validity = validity25Years
	if o.Validity != "" {
		spec.Validity = o.Validity
	}
	return []scenarioEntry{{
		spec: spec,
		comment: "Android app signing key, in the PKCS#12 keystore " + ScenarioAndroidSigning + ".pfx. Sign with\n" +
			"  apksigner sign --ks " + ScenarioAndroidSigning + ".pfx --ks-type PKCS12 app.apk\n" +
			"or in Gradle with storeFile file(\"" + ScenarioAndroidSigning + ".pfx\") and storeType \"pkcs12\" in signingConfigs;\n" +
			"keytool -list -keystore " + ScenarioAndroidSigning + ".pfx shows the key alias. With Play App Signing, register\n" +
			ScenarioAndroidSigning + ".crt as the upload certificate; without it, losing this key means the app can never be updated.",
		fieldComments: map[string]string{
			"validity": "25 years: Android only accepts an update signed with the same key, so it must outlive the app.",
			"target":   "The android target makes an RSA-4096 key unless keyType is set.",
		},
	}}, nil
}

func codeSignScenario(o *ScenarioOptions) ([]scenarioEntry, error) {
	target := o.Target
	if target == "" {
		target = windows10Target
	}
	profile, err := GetProfile(target)
	if err != nil {
		return nil, err
	}

	spec := o.subject(o.Organization+" Code Signing", ScenarioCodeSign)
	spec.CodeSigning = true
	spec.Target = target
	spec.KeyType = o.KeyType
	spec.Validity = validity3Years
	if o.Validity != "" {
		spec.Validity = o.Validity
	}

	comment := "Self-signed code signing certificate. Machines must trust " + ScenarioCodeSign + ".crt to accept what it signs."
	if o.ExternalRoot {
		comment = "Code signing certificate, signed by the root CA on the YubiKey: run this spec with certtool --yubikey --spec.\nMachines that trust the YubiKey root accept what it signs."
	}
	comment += "\nAnyone who has its key can sign code as you; see docs/use-cases/code-signing.md for signing and verifying."
	fieldComments := map[string]string{
		"target": "windows7, windows10, windows11, or linux. The key type comes from the target unless keyType is set.",
	}
	if profile.LegacyPFX {
		fieldComments["target"] += "\nwindows7 writes a legacy .pfx (3DES with a SHA-1 MAC) that is easy to brute-force: use a long random password."
	}
	if profile.OutputPFX {
		comment += "\nThe key is also written to " + ScenarioCodeSign + ".pfx for signtool."
	}
	return []scenarioEntry{{spec: spec, comment: comment, fieldComments: fieldComments}}, nil
}

func proxyScenario(o *ScenarioOptions) ([]scenarioEntry, error) {
	spec := o.subject(o.Organization+" TLS Inspection CA", ScenarioProxy+"-ca")
	spec.CertificateAuthority = true
	spec.KeyType = scenarioRSAKeyType
	spec.Validity = validity3Years
	maxPathLen := 0
	spec.MaxPathLen = &maxPathLen

	comment := "CA for a TLS-inspecting proxy, which signs a certificate for every site its clients visit. Its key sits on the proxy\n" +
		"and can impersonate any site to the machines that trust it: install " + ScenarioProxy + "-ca.crt only on managed machines.\n" +
		"Squid: tls-cert=" + ScenarioProxy + "-ca.crt tls-key=" + ScenarioProxy + "-ca.key on an ssl-bump http_port.\n" +
		"mitmproxy: cat " + ScenarioProxy + "-ca.key " + ScenarioProxy + "-ca.crt > ~/.mitmproxy/mitmproxy-ca.pem"
	if o.ExternalRoot {
		comment = "Signed by the root CA on the YubiKey: run this spec with certtool --yubikey --spec.\n" + comment
	}
	return []scenarioEntry{{
		spec:    spec,
		comment: comment,
		fieldComments: map[string]string{
			"keyType":    "RSA, which every proxy and client supports.",
			"maxPathLen": "0: the proxy may sign site certificates but not other CAs.",
		},
	}}, nil
}

// marshalScenario writes entries as YAML with their comments.
func marshalScenario(entries []scenarioEntry) ([]byte, error) {
	var doc yaml.Node
	if err := doc.Encode(scenarioSpecs(entries)); err != nil {
		return nil, err
	}
	commentSequence(&doc, entries)
	return yaml.Marshal(&doc)
}

// scenarioSpecs returns the specs of entries, with their children.
func scenarioSpecs(entries []scenarioEntry) []CertificateSpec {
	specs := make([]CertificateSpec, len(entries))
	for i, e := range entries {
		specs[i] = e.spec
		specs[i].Children = scenarioSpecs(e.children)
	}
	return specs
}

// commentSequence adds the comments of entries to seq, the YAML sequence
// encoded from them.
func commentSequence(seq *yaml.Node, entries []scenarioEntry) {
	for i, item := range seq.Content {
		e := entries[i]
		item.HeadComment = e.comment
		// A mapping holds its keys and values in turn.
		for j := 0; j+1 < len(item.Content); j += 2 {
			key, value := item.Content[j], item.Content[j+1]
			if c, ok := e.fieldComments[key.Value]; ok {
				key.HeadComment = c
			}
			if key.Value == "children" {
				commentSequence(value, e.children)
			}
		}
	}
}
