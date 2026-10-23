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
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/cloudfra/certtool/internal/logging"
	certlib "github.com/cloudfra/certtool/pkg/certtool"
)

// runScenario writes the spec of the --scenario values. With --export-spec
// it only writes the spec there, and returns nil. Otherwise it writes the spec
// to --output-dir, next to the certificates, and returns the arguments that
// generate them from it as --spec would.
func runScenario(ctx context.Context, args Args) (*Args, error) {
	scenarios := splitStrings(args.Scenario)
	if err := validateScenario(args, scenarios); err != nil {
		return nil, err
	}

	opts, err := scenarioOptions(args)
	if err != nil {
		return nil, err
	}
	if args.ExportSpec != "" {
		if args.ExportSpec != "-" {
			opts.SpecPath = args.ExportSpec
		}
		body, err := certlib.ScenarioSpec(scenarios, opts)
		if err != nil {
			return nil, err
		}
		return nil, writeSpecData(ctx, body, args.ExportSpec)
	}

	path := filepath.Join(args.OutputDir, strings.Join(scenarios, "+")+".yaml")
	opts.SpecPath, opts.OutputDir, opts.Generate = path, args.OutputDir, true
	body, err := certlib.ScenarioSpec(scenarios, opts)
	if err != nil {
		return nil, err
	}
	if err := writeScenarioSpec(ctx, body, path, args.Overwrite); err != nil {
		return nil, err
	}

	// Generate from the spec, which now holds every scenario input.
	defaults := DefaultArgs()
	args.Scenario, args.Spec = "", path
	args.Hostnames, args.Clients, args.Target, args.KeyType, args.Validity = "", "", "", "", defaults.Validity
	return &args, nil
}

// writeScenarioSpec writes the spec of a scenario to path, unless path
// already holds it. A different spec there is an error, because it may hold
// edits, unless overwrite is set.
func writeScenarioSpec(ctx context.Context, data []byte, path string, overwrite bool) error {
	existing, err := os.ReadFile(filepath.Clean(path))
	switch {
	case err == nil && bytes.Equal(existing, data):
		logging.FromContext(ctx).Info("spec already written", "path", path)
		return nil
	case err == nil && !overwrite:
		return fmt.Errorf("%s already exists and differs from the spec --scenario writes, perhaps because it was edited; to generate from it, run certtool --spec %s --output-dir %s instead; to replace it and every certificate, add --overwrite", path, path, filepath.Dir(path))
	case err != nil && !errors.Is(err, fs.ErrNotExist):
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	return writeSpecData(ctx, data, path)
}

// validateScenario rejects options that --scenario does not use, so a flag is
// never silently ignored.
func validateScenario(args Args, scenarios []string) error {
	for _, s := range scenarios {
		if !slices.Contains(certlib.Scenarios(), s) {
			return fmt.Errorf("--scenario %q is not a scenario; use one or more of %s, separated by commas", s, strings.Join(certlib.Scenarios(), ", "))
		}
	}
	defaults := DefaultArgs()
	unused := []struct {
		flag string
		set  bool
		// generates is set for the options that apply when --scenario
		// generates the certificates, rather than only writing the spec
		// to --export-spec.
		generates bool
	}{
		{"--public-certificate", args.PublicCertificate != defaults.PublicCertificate, false},
		{"--private-key", args.PrivateKey != defaults.PrivateKey, false},
		{"--ca", args.CA, false},
		{"--max-path-len", args.MaxPathLen != defaults.MaxPathLen, false},
		{"--permitted-dns-domains", args.PermittedDNSDomains != "", false},
		{"--permitted-ip-ranges", args.PermittedIPRanges != "", false},
		{"--common-name", args.CommonName != "", false},
		{"--parent-public-certificate", args.ParentPublicCertificate != "", false},
		{"--parent-private-key", args.ParentPrivateKey != "", false},
		{"--code-sign", args.CodeSigning, false},
		{"--pfx-output", args.PFXOutput != defaults.PFXOutput, false},
		{"--pfx-password", args.PFXPassword != "", false},
		{"--spec", args.Spec != "", false},
		{"--chain", args.Chain != "", false},
		{"--name-prefix", args.NamePrefix != "", false},
		{"--output-dir", args.OutputDir != defaults.OutputDir, true},
		{"--overwrite", args.Overwrite, true},
		{"--yubikey-generate-root", args.YubiKeyGenerateRoot, false},
		{"--yubikey-serial", args.YubiKeySerial != "", true},
		{"--yubikey-slot", args.YubiKeySlot != defaults.YubiKeySlot, true},
		{"--yubikey-pin", args.YubiKeyPIN != "", true},
		{"--yubikey-management-key", args.YubiKeyManagementKey != "", true},
		{"--yubikey-touch-policy", args.YubiKeyTouchPolicy != defaults.YubiKeyTouchPolicy, false},
		{"--yubikey-overwrite", args.YubiKeyOverwrite, false},
		{"--encrypt-to", args.EncryptTo != "", true},
		{"--age-identity-file", args.AgeIdentityFile != "", true},
		{"--age-yubikey", args.AgeYubiKey, true},
	}
	for _, u := range unused {
		switch {
		case u.set && !u.generates:
			return fmt.Errorf("%s does not apply to --scenario; edit the spec it writes instead", u.flag)
		case u.set && args.ExportSpec != "":
			return fmt.Errorf("%s does not apply to --scenario with --export-spec, which only writes a spec; leave out --export-spec to generate the certificates too", u.flag)
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
