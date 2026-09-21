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

// Package main is the entry point for certtool. It only parses the command
// line and hands the result to pkg/certtool; everything the tool does lives
// there, so it can be reused or reimplemented behind a different front end.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/cloudfra/certtool/internal"
	"github.com/cloudfra/certtool/internal/logging"
	"github.com/cloudfra/certtool/pkg/certtool"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run parses args, runs the tool and returns the process exit code.
func run(args []string, stdout, stderr io.Writer) int {
	opts, showVersion, err := parseFlags(args, stderr)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}

	if showVersion {
		if _, err := fmt.Fprintf(stdout, "certtool %s (built %s)\n", internal.Version(), internal.Buildstamp()); err != nil {
			return 1
		}
		return 0
	}

	logging.Init()
	if err := certtool.Run(opts); err != nil {
		slog.Error("certtool failed", "error", err)
		return 1
	}
	return 0
}

// parseFlags binds every command-line flag to the matching certtool.Options
// field, starting from the library defaults, and parses args. Flag errors and
// usage are written to output.
func parseFlags(args []string, output io.Writer) (opts certtool.Options, showVersion bool, err error) {
	opts = certtool.DefaultOptions()
	fs := flag.NewFlagSet("certtool", flag.ContinueOnError)
	fs.SetOutput(output)

	fs.StringVar(&opts.PublicCertificate, "public-certificate", opts.PublicCertificate, "X.509 public certificate file to generate.")
	fs.StringVar(&opts.PrivateKey, "private-key", opts.PrivateKey, "Private key file to generate.")

	fs.BoolVar(&opts.CA, "ca", opts.CA, "Generates a root certificate. Use this to establish a chain of trust with derived certificates.")

	fs.StringVar(&opts.CommonName, "common-name", opts.CommonName, "Common Name (CN) field of the X.509 certificate subject. Defaults to the --organization value.")
	fs.StringVar(&opts.Country, "country", opts.Country, "Country (C) field of the X.509 certificate subject (e.g. US, CA, GB).")
	fs.StringVar(&opts.Organization, "organization", opts.Organization, "Organization (O) field of the X.509 certificate subject.")
	fs.StringVar(&opts.OrganizationalUnit, "organizational-unit", opts.OrganizationalUnit, "Organizational Unit (OU) field of the X.509 certificate subject.")
	fs.StringVar(&opts.Locality, "locality", opts.Locality, "Locality (L) field of the X.509 certificate subject, typically the city name.")
	fs.StringVar(&opts.Province, "province", opts.Province, "Province or state (ST) field of the X.509 certificate subject.")

	fs.DurationVar(&opts.Validity, "validity", opts.Validity, "How long the certificate is valid for, as a Go duration (e.g. 8760h, 720h, 24h).")
	fs.StringVar(&opts.Hostnames, "hostnames", opts.Hostnames, "Comma-separated list of hostnames and IP addresses to include as Subject Alternative Names (SANs).")
	fs.StringVar(&opts.KeyType, "key-type", opts.KeyType, "Key algorithm and length. Supported values: RSA-2048, RSA-4096, ECDSA-224, ECDSA-256, ECDSA-384, ECDSA-521. Default: RSA-2048, or the profile default for --code-sign.")
	fs.StringVar(&opts.Ports, "ports", opts.Ports, "Comma-separated list of ports to include as Subject Alternative Names (SANs). Ports are expanded on the hostnames that are specified.")

	fs.StringVar(&opts.ParentPublicCertificate, "parent-public-certificate", opts.ParentPublicCertificate, "(optional) Parent public certificate. If set, the output certificate will trust the parent.")
	fs.StringVar(&opts.ParentPrivateKey, "parent-private-key", opts.ParentPrivateKey, "(optional) Parent private key. Required if -parent-public-certificate is set, private key for the parent public certificate.")

	fs.BoolVar(&opts.CodeSigning, "code-sign", opts.CodeSigning, "Generates a code signing certificate for binary signing instead of a TLS certificate.")
	fs.StringVar(&opts.Target, "target", opts.Target, "Platform profile for --code-sign. Values: windows7 (win7/windows8/win8), windows10 (win10), windows11 (win11), linux. Default: windows10.")
	fs.StringVar(&opts.PFXOutput, "pfx-output", opts.PFXOutput, "Output path for the PKCS#12 (.pfx) file. Used with --code-sign for Windows targets.")
	fs.StringVar(&opts.PFXPassword, "pfx-password", opts.PFXPassword, "Password for the PKCS#12 (.pfx) file. Empty means no password.")

	fs.StringVar(&opts.Spec, "spec", opts.Spec, "Path to a YAML file specifying certificates to generate. See CertificateSpec for the format.")
	fs.StringVar(&opts.Chain, "chain", opts.Chain, "Generate a certificate hierarchy from the number of certificates per layer. A single number produces that many standalone leaf certificates (e.g. 3). Comma-separated numbers set the width of each layer from the root down, the last being the leaves (e.g. 1,1 = root CA and leaf; 1,2,3 = 1 root, 2 intermediates per root, 3 leaves per intermediate).")
	fs.StringVar(&opts.NamePrefix, "name-prefix", opts.NamePrefix, "Prefix placed in front of the common name of every certificate generated by --chain (e.g. prod). Empty by default.")
	fs.StringVar(&opts.OutputDir, "output-dir", opts.OutputDir, "Output directory for certificates generated by --spec or --chain.")
	fs.StringVar(&opts.ExportSpec, "export-spec", opts.ExportSpec, "Export the certificate spec as a YAML file instead of generating certificates. Works with --chain or flag-based mode.")

	fs.BoolVar(&showVersion, "version", false, "Print version and build information, then exit.")

	err = fs.Parse(args)
	return opts, showVersion, err
}
