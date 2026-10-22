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

// Scenario names accepted by ScenarioSpec.
const (
	// ScenarioWeb is a root CA and an issuing CA, name constrained to the
	// hostnames, that sign one server certificate.
	ScenarioWeb = "web"
	// ScenarioLocalDev is a self-signed certificate for localhost.
	ScenarioLocalDev = "local-dev"
	// ScenarioMTLS is a root CA and an issuing CA that sign a server
	// certificate and client certificates for mutual TLS.
	ScenarioMTLS = "mtls"
	// ScenarioCodeSign is a self-signed code signing certificate.
	ScenarioCodeSign = "code-sign"
)

// Scenarios returns the scenario names ScenarioSpec accepts.
func Scenarios() []string {
	return []string{ScenarioWeb, ScenarioLocalDev, ScenarioMTLS, ScenarioCodeSign}
}

// Default validities of the certificates a scenario makes, as spec durations.
const (
	scenarioRootValidity       = "87600h" // 10 years
	scenarioIssuingValidity    = "26280h" // 3 years
	scenarioServerValidity     = "2160h"  // 90 days
	scenarioLocalDevValidity   = "8760h"  // 1 year
	scenarioCodeSignValidity   = "26280h" // 3 years
	scenarioCAKeyType          = "ECDSA-384"
	scenarioIssuingCAKeyType   = "ECDSA-256"
	scenarioDefaultLeafKeyType = "ECDSA-256"
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

	// Hostnames are the DNS names and IP addresses of the server certificate.
	// The web and mtls scenarios need at least one; their CAs are name
	// constrained to them.
	Hostnames []string
	// Clients are the common names of the mtls client certificates. The mtls
	// scenario needs at least one.
	Clients []string

	// KeyType is the key type of the leaf certificates, such as "ECDSA-256".
	// Empty uses ECDSA-256, or the target profile's key type for code signing.
	// CAs always use ECDSA.
	KeyType string
	// Validity is the validity of the leaf certificates, as a Go duration.
	// Empty uses the scenario's default.
	Validity string

	// Target is the code signing target. Empty uses windows10.
	Target string
	// PFXPasswordEnv is the environment variable a code signing .pfx reads
	// its password from. Required by code-sign for targets that write a .pfx.
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
		if seen[name] {
			return nil, fmt.Errorf("scenario %q is given twice", name)
		}
		seen[name] = true

		var added []scenarioEntry
		var err error
		switch name {
		case ScenarioWeb:
			added, err = webScenario(opts)
		case ScenarioLocalDev:
			added = localDevScenario(opts)
		case ScenarioMTLS:
			added, err = mtlsScenario(opts)
		case ScenarioCodeSign:
			added, err = codeSignScenario(opts)
		default:
			return nil, fmt.Errorf("unknown scenario %q; use one or more of %s", name, strings.Join(Scenarios(), ", "))
		}
		if err != nil {
			return nil, err
		}
		entries = append(entries, added...)
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

// subject returns a spec with the subject fields of opts.
func (opts *ScenarioOptions) subject(commonName, filename string) CertificateSpec {
	return CertificateSpec{
		CommonName:         commonName,
		Organization:       opts.Organization,
		OrganizationalUnit: opts.OrganizationalUnit,
		Country:            opts.Country,
		Locality:           opts.Locality,
		Province:           opts.Province,
		Filename:           filename,
	}
}

func (opts *ScenarioOptions) leafKeyType() string {
	if opts.KeyType != "" {
		return opts.KeyType
	}
	return scenarioDefaultLeafKeyType
}

func (opts *ScenarioOptions) leafValidity(fallback string) string {
	if opts.Validity != "" {
		return opts.Validity
	}
	return fallback
}

func webScenario(opts ScenarioOptions) ([]scenarioEntry, error) {
	if len(opts.Hostnames) == 0 {
		return nil, fmt.Errorf("scenario %q needs the hostnames of the server certificate", ScenarioWeb)
	}
	server := serverEntry(&opts, ScenarioWeb)
	return tlsHierarchy(&opts, ScenarioWeb, "Web", []scenarioEntry{server})
}

func mtlsScenario(opts ScenarioOptions) ([]scenarioEntry, error) {
	if len(opts.Hostnames) == 0 {
		return nil, fmt.Errorf("scenario %q needs the hostnames of the server certificate", ScenarioMTLS)
	}
	if len(opts.Clients) == 0 {
		return nil, fmt.Errorf("scenario %q needs the names of the client certificates", ScenarioMTLS)
	}
	leaves := []scenarioEntry{serverEntry(&opts, ScenarioMTLS)}
	seen := map[string]bool{}
	for _, client := range opts.Clients {
		filename := ScenarioMTLS + "-client-" + slugify(client)
		if seen[filename] {
			return nil, fmt.Errorf("client %q is given twice", client)
		}
		seen[filename] = true

		spec := opts.subject(client, filename)
		spec.KeyType = opts.leafKeyType()
		spec.Validity = opts.leafValidity(scenarioServerValidity)
		leaves = append(leaves, scenarioEntry{
			spec:    spec,
			comment: "Client certificate for " + client + ". Every TLS certificate certtool makes is valid for client authentication.\nThe client sends " + filename + ".crt followed by " + ScenarioMTLS + "-issuing-ca.crt, so the server only needs to trust the root.",
		})
	}
	return tlsHierarchy(&opts, ScenarioMTLS, "mTLS", leaves)
}

// serverEntry returns the server certificate of the web and mtls scenarios.
func serverEntry(opts *ScenarioOptions, scenario string) scenarioEntry {
	filename := scenario + "-server"
	spec := opts.subject(hostWithoutPort(opts.Hostnames[0]), filename)
	spec.KeyType = opts.leafKeyType()
	spec.Validity = opts.leafValidity(scenarioServerValidity)
	spec.Hostnames = slices.Clone(opts.Hostnames)
	return scenarioEntry{
		spec:    spec,
		comment: "Server certificate. Serve " + filename + ".crt followed by " + scenario + "-issuing-ca.crt, so clients only need to trust the root.\nTo add a server, copy this entry with a new commonName, hostnames, and filename.",
		fieldComments: map[string]string{
			"validity": "Short-lived. To renew, delete " + filename + ".crt and " + filename + ".key, then run the spec again.",
		},
	}
}

// tlsHierarchy returns a root CA, unless the root is external, and an issuing
// CA that signs leaves. The top CA is name constrained to the hostnames.
func tlsHierarchy(opts *ScenarioOptions, scenario, label string, leaves []scenarioEntry) ([]scenarioEntry, error) {
	dnsDomains, ipRanges, err := hostnameConstraints(opts.Hostnames)
	if err != nil {
		return nil, err
	}
	constraintComments := map[string]string{
		"permittedDNSDomains": "Name constraints: certificates below this CA may only use these names and their subdomains.\nAdd a domain before you issue a certificate for it; changing them later means regenerating the CA and everything below it.",
		"permittedIPRanges":   "The IP addresses certificates below this CA may use.",
	}
	if len(ipRanges) == 0 {
		constraintComments["permittedDNSDomains"] += "\nIP addresses are not limited, so certtool still adds 127.0.0.1; add permittedIPRanges to limit them."
	}

	issuing := opts.subject(opts.Organization+" "+label+" Issuing CA", scenario+"-issuing-ca")
	issuing.CertificateAuthority = true
	issuing.KeyType = scenarioIssuingCAKeyType
	issuing.Validity = scenarioIssuingValidity
	issuingEntry := scenarioEntry{
		spec:          issuing,
		comment:       "Issuing CA: signs the day-to-day certificates. Renew it well before it expires, because a certificate is only valid while its issuers are.",
		fieldComments: map[string]string{"validity": "3 years."},
		children:      leaves,
	}

	if opts.ExternalRoot {
		issuingEntry.spec.PermittedDNSDomains = dnsDomains
		issuingEntry.spec.PermittedIPRanges = ipRanges
		issuingEntry.comment = "Issuing CA, signed by the root CA on the YubiKey: run this spec with certtool --yubikey --spec.\n" + issuingEntry.comment
		for k, v := range constraintComments {
			issuingEntry.fieldComments[k] = v
		}
		return []scenarioEntry{issuingEntry}, nil
	}

	root := opts.subject(opts.Organization+" "+label+" Root CA", scenario+"-root-ca")
	root.CertificateAuthority = true
	root.KeyType = scenarioCAKeyType
	root.Validity = scenarioRootValidity
	root.PermittedDNSDomains = dnsDomains
	root.PermittedIPRanges = ipRanges
	rootComments := map[string]string{"validity": "10 years."}
	for k, v := range constraintComments {
		rootComments[k] = v
	}
	return []scenarioEntry{{
		spec:          root,
		comment:       "Root CA: install " + scenario + "-root-ca.crt on the clients. Its key can sign anything within the name constraints,\nso move " + scenario + "-root-ca.key offline once the issuing CA exists, or keep the root on a YubiKey (--yubikey).",
		fieldComments: rootComments,
		children:      []scenarioEntry{issuingEntry},
	}}, nil
}

// hostnameConstraints returns name constraints that permit exactly the given
// hostnames: each DNS name and its subdomains, and each IP address.
func hostnameConstraints(hostnames []string) (dnsDomains, ipRanges []string, err error) {
	for _, hostname := range hostnames {
		if err := ValidateHostname(hostname); err != nil {
			return nil, nil, err
		}
		host := strings.TrimSuffix(hostWithoutPort(strings.TrimSpace(hostname)), ".")
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

func localDevScenario(opts ScenarioOptions) []scenarioEntry {
	commonName := "localhost"
	if len(opts.Hostnames) > 0 {
		commonName = hostWithoutPort(opts.Hostnames[0])
	}
	spec := opts.subject(commonName, ScenarioLocalDev)
	spec.KeyType = opts.leafKeyType()
	spec.Validity = opts.leafValidity(scenarioLocalDevValidity)
	spec.Hostnames = append(slices.Clone(opts.Hostnames), "::1")

	comment := "Self-signed certificate for this machine. certtool adds localhost and 127.0.0.1 itself.\nTrust " + ScenarioLocalDev + ".crt only on the machine that holds " + ScenarioLocalDev + ".key; see docs/use-cases/local-development.md."
	if opts.ExternalRoot {
		comment = "Certificate for this machine, signed by the root CA on the YubiKey: run this spec with certtool --yubikey --spec.\ncerttool adds localhost and 127.0.0.1 itself. Trust the YubiKey root's certificate to trust it."
	}
	return []scenarioEntry{{
		spec:          spec,
		comment:       comment,
		fieldComments: map[string]string{"hostnames": "Add the names you browse to, such as myapp.localhost."},
	}}
}

func codeSignScenario(opts ScenarioOptions) ([]scenarioEntry, error) {
	target := opts.Target
	if target == "" {
		target = windows10Target
	}
	profile, err := GetProfile(target)
	if err != nil {
		return nil, err
	}

	spec := opts.subject(opts.Organization+" Code Signing", ScenarioCodeSign)
	spec.CodeSigning = true
	spec.Target = target
	spec.KeyType = opts.KeyType
	spec.Validity = opts.leafValidity(scenarioCodeSignValidity)

	comment := "Self-signed code signing certificate. Machines must trust " + ScenarioCodeSign + ".crt to accept what it signs."
	if opts.ExternalRoot {
		comment = "Code signing certificate, signed by the root CA on the YubiKey: run this spec with certtool --yubikey --spec.\nMachines that trust the YubiKey root accept what it signs."
	}
	fieldComments := map[string]string{
		"target": "windows7, windows10, windows11, or linux. The key type comes from the target unless keyType is set.",
	}
	if profile.LegacyPFX {
		fieldComments["target"] += "\nwindows7 writes a legacy .pfx (3DES with a SHA-1 MAC) that is easy to brute-force: use a long random password."
	}
	if profile.OutputPFX {
		if opts.PFXPasswordEnv == "" {
			return nil, fmt.Errorf("scenario %q needs the environment variable that holds the .pfx password", ScenarioCodeSign)
		}
		spec.PFXPasswordEnv = opts.PFXPasswordEnv
		comment += "\nThe key is also written to " + ScenarioCodeSign + ".pfx for signtool. Anyone who has the key can sign code as you."
		fieldComments["pfxPasswordEnv"] = "Set this environment variable to a long random password before running the spec. The spec never stores the password."
	}
	return []scenarioEntry{{spec: spec, comment: comment, fieldComments: fieldComments}}, nil
}

// marshalScenario writes entries as YAML with their comments.
func marshalScenario(entries []scenarioEntry) ([]byte, error) {
	specs := scenarioSpecs(entries)
	var doc yaml.Node
	if err := doc.Encode(specs); err != nil {
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
