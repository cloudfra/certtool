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
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
)

// Run performs everything the certtool command does for the given options: it
// validates them, generates the certificates and writes the output files.
//
// What it does depends on the options that are set:
//   - Spec generates the certificates described by a YAML spec file.
//   - Chain generates a hierarchy from layer widths (see ChainToSpec).
//   - ExportSpec writes the resolved spec as YAML instead of generating
//     certificates, from Spec, Chain, or the single-certificate options.
//   - Otherwise a single certificate and key are written to PublicCertificate
//     and PrivateKey, or a PKCS#12 bundle to PFXOutput for a Windows code
//     signing certificate.
//
// Progress and warnings are logged with the default log/slog logger, so a
// caller chooses where they go with slog.SetDefault. Run returns an error for
// invalid options and for anything that fails while generating or writing.
//
// Options should start from DefaultOptions.
func Run(opts Options) error {
	opts.warnAboutIgnoredOptions()

	if opts.Chain != "" && opts.Spec != "" {
		return fmt.Errorf("--chain and --spec are mutually exclusive")
	}

	if opts.Spec == "" && opts.Chain == "" && opts.ExportSpec == "" {
		return opts.generateCertificate()
	}

	specs, err := opts.resolveSpecs()
	if err != nil {
		return err
	}
	if opts.ExportSpec != "" {
		return writeSpec(specs, opts.ExportSpec)
	}
	return generateAndLog(specs, opts.OutputDir)
}

// warnAboutIgnoredOptions logs a warning for options that have no effect
// because the option they depend on is not set.
func (o *Options) warnAboutIgnoredOptions() {
	if o.Target != "" && !o.CodeSigning {
		slog.Warn("--target is set but --code-sign is not; --target will be ignored")
	}
	if o.NamePrefix != "" && o.Chain == "" {
		slog.Warn("--name-prefix is set but --chain is not; --name-prefix will be ignored")
	}
}

// resolveSpecs returns the specs described by Spec, Chain, or, when neither is
// set, by the single-certificate options.
func (o *Options) resolveSpecs() ([]CertificateSpec, error) {
	switch {
	case o.Spec != "":
		return ReadSpec(o.Spec)
	case o.Chain != "":
		widths, err := chainWidths(o.Chain)
		if err != nil {
			return nil, err
		}
		return ChainToSpec(widths, o.CommonName, o.Organization, o.NamePrefix)
	default:
		return o.flagsToSpec()
	}
}

// generateCertificate writes a single certificate described by the options.
func (o *Options) generateCertificate() error {
	args, err := o.args()
	if err != nil {
		return err
	}
	kp, err := GenerateKeyPair(args)
	if err != nil {
		return err
	}
	if len(kp.PFX) > 0 {
		return WritePFX(kp, o.PFXOutput)
	}
	return WriteKeyPair(kp, o.PublicCertificate, o.PrivateKey)
}

// writeSpec writes specs to path as YAML.
func writeSpec(specs []CertificateSpec, path string) error {
	data, err := MarshalSpec(specs)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Clean(path), data, 0o600); err != nil {
		return err
	}
	slog.Info("spec written", "path", path)
	return nil
}

// generateAndLog generates the certificates described by specs into outputDir
// and logs each one.
func generateAndLog(specs []CertificateSpec, outputDir string) error {
	results, err := GenerateFromSpec(specs, outputDir)
	if err != nil {
		return err
	}

	for _, r := range results {
		if r.PFXPath != "" {
			slog.Info("generated certificate", "cn", r.CommonName, "cert", r.CertPath, "key", r.KeyPath, "pfx", r.PFXPath)
		} else {
			slog.Info("generated certificate", "cn", r.CommonName, "cert", r.CertPath, "key", r.KeyPath)
		}
	}
	return nil
}
