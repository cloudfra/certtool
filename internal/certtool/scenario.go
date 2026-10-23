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
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	certlib "github.com/cloudfra/certtool/pkg/certtool"
)

// runScenario writes the spec of the --scenario values to --export-spec.
func runScenario(ctx context.Context, args Args) error {
	scenarios := splitStrings(args.Scenario)
	if err := validateScenario(args, scenarios); err != nil {
		return err
	}

	opts, err := scenarioOptions(args)
	if err != nil {
		return err
	}
	body, err := certlib.ScenarioSpec(scenarios, opts)
	if err != nil {
		return err
	}
	return writeSpecData(ctx, body, args.ExportSpec)
}

// validateScenario rejects options that --scenario does not use, so a flag is
// never silently ignored.
func validateScenario(args Args, scenarios []string) error {
	for _, s := range scenarios {
		if !slices.Contains(certlib.Scenarios(), s) {
			return fmt.Errorf("--scenario %q is not a scenario; use one or more of %s, separated by commas", s, strings.Join(certlib.Scenarios(), ", "))
		}
	}
	if args.ExportSpec == "" {
		return errors.New("--scenario writes a spec instead of certificates: set --export-spec to the file to write, or - for standard output, then run it with --spec")
	}

	defaults := DefaultArgs()
	unused := []struct {
		flag string
		set  bool
	}{
		{"--public-certificate", args.PublicCertificate != defaults.PublicCertificate},
		{"--private-key", args.PrivateKey != defaults.PrivateKey},
		{"--ca", args.CA},
		{"--max-path-len", args.MaxPathLen != defaults.MaxPathLen},
		{"--permitted-dns-domains", args.PermittedDNSDomains != ""},
		{"--permitted-ip-ranges", args.PermittedIPRanges != ""},
		{"--common-name", args.CommonName != ""},
		{"--parent-public-certificate", args.ParentPublicCertificate != ""},
		{"--parent-private-key", args.ParentPrivateKey != ""},
		{"--code-sign", args.CodeSigning},
		{"--pfx-output", args.PFXOutput != defaults.PFXOutput},
		{"--pfx-password", args.PFXPassword != ""},
		{"--spec", args.Spec != ""},
		{"--chain", args.Chain != ""},
		{"--name-prefix", args.NamePrefix != ""},
		{"--output-dir", args.OutputDir != defaults.OutputDir},
		{"--overwrite", args.Overwrite},
		{"--yubikey-generate-root", args.YubiKeyGenerateRoot},
		{"--yubikey-serial", args.YubiKeySerial != ""},
		{"--yubikey-slot", args.YubiKeySlot != defaults.YubiKeySlot},
		{"--yubikey-pin", args.YubiKeyPIN != ""},
		{"--yubikey-management-key", args.YubiKeyManagementKey != ""},
		{"--yubikey-touch-policy", args.YubiKeyTouchPolicy != defaults.YubiKeyTouchPolicy},
		{"--yubikey-overwrite", args.YubiKeyOverwrite},
		{"--encrypt-to", args.EncryptTo != ""},
		{"--age-identity-file", args.AgeIdentityFile != ""},
		{"--age-yubikey", args.AgeYubiKey},
	}
	for _, u := range unused {
		if u.set {
			return fmt.Errorf("%s does not apply to --scenario, which only writes a spec; edit the spec instead", u.flag)
		}
	}

	var usesHostnames, usesClients, usesTarget bool
	for _, s := range scenarios {
		info, _ := certlib.LookupScenario(s)
		usesHostnames = usesHostnames || info.Hostnames != certlib.InputUnused
		usesClients = usesClients || info.Clients != certlib.InputUnused
		usesTarget = usesTarget || info.Target
		switch {
		case info.Hostnames == certlib.InputRequired && args.Hostnames == "":
			return fmt.Errorf("--scenario %s needs --hostnames: %s", s, info.HostnamesHelp)
		case info.Clients == certlib.InputRequired && args.Clients == "":
			return fmt.Errorf("--scenario %s needs --clients: %s", s, info.ClientsHelp)
		case info.SelfSigned && args.YubiKey:
			return fmt.Errorf("--scenario %s makes a self-signed certificate, so it cannot be combined with --yubikey", s)
		}
	}
	switch {
	case args.Target != "" && !usesTarget:
		return fmt.Errorf("--target does not apply to --scenario %s; it sets the code-sign target", args.Scenario)
	case args.Clients != "" && !usesClients:
		return fmt.Errorf("--clients does not apply to --scenario %s, which makes no client certificates", args.Scenario)
	case args.Hostnames != "" && !usesHostnames:
		return fmt.Errorf("--hostnames does not apply to --scenario %s, which makes no TLS certificates", args.Scenario)
	}
	return nil
}

// scenarioOptions converts the options to the inputs of a scenario.
func scenarioOptions(args Args) (certlib.ScenarioOptions, error) {
	defaults := DefaultArgs()
	// The default subject fields are certtool's own, so only those the user
	// chose go into the spec.
	unlessDefault := func(value, defaultValue string) string {
		if value == defaultValue {
			return ""
		}
		return value
	}

	hostnames, err := splitHostnames(args.Hostnames)
	if err != nil {
		return certlib.ScenarioOptions{}, err
	}

	opts := certlib.ScenarioOptions{
		Organization:       args.Organization,
		OrganizationalUnit: unlessDefault(args.OrganizationalUnit, defaults.OrganizationalUnit),
		Country:            unlessDefault(args.Country, defaults.Country),
		Locality:           unlessDefault(args.Locality, defaults.Locality),
		Province:           unlessDefault(args.Province, defaults.Province),
		Hostnames:          hostnames,
		Clients:            splitStrings(args.Clients),
		Target:             args.Target,
		PFXPasswordEnv:     PFXPasswordEnv,
		ExternalRoot:       args.YubiKey,
	}
	if args.ExportSpec != "-" {
		opts.SpecPath = args.ExportSpec
	}
	if opts.Organization == "" {
		return certlib.ScenarioOptions{}, errors.New("--scenario needs --organization to name the certificates")
	}
	if args.KeyType != "" {
		algorithm, length, err := stringToKeyType(args.KeyType)
		if err != nil {
			return certlib.ScenarioOptions{}, err
		}
		opts.KeyType = fmt.Sprintf("%s-%d", algorithm, length)
	}
	if args.Validity != defaults.Validity {
		if args.Validity <= 0 {
			return certlib.ScenarioOptions{}, fmt.Errorf("--validity must be a positive duration, got %s", args.Validity)
		}
		opts.Validity = specDuration(args.Validity)
	}
	return opts, nil
}

// specDuration formats d the way the docs write validities, such as 2160h.
func specDuration(d time.Duration) string {
	if d%time.Hour == 0 {
		return fmt.Sprintf("%dh", d/time.Hour)
	}
	return d.String()
}
