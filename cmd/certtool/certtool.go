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

// Package main is the entry point for certtool.
package main

import (
	"flag"
	"log/slog"
	"os"

	"github.com/cloudfra/certtool/internal/certtool"
	"github.com/cloudfra/certtool/internal/logging"
)

func main() {
	args, err := parseFlags(flag.CommandLine, os.Args[1:])
	if err != nil {
		os.Exit(2)
	}
	logging.Init()

	if err := certtool.Run(args); err != nil {
		slog.Error("certtool failed", "error", err)
		os.Exit(1)
	}
}

// parseFlags parses the command line into certtool.Args. The flag set reports
// parse errors itself.
func parseFlags(fs *flag.FlagSet, arguments []string) (certtool.Args, error) {
	args := certtool.DefaultArgs()

	fs.StringVar(&args.PublicCertificate, "public-certificate", args.PublicCertificate, "X.509 public certificate file to generate.")
	fs.StringVar(&args.PrivateKey, "private-key", args.PrivateKey, "Private key file to generate.")

	fs.BoolVar(&args.CA, "ca", args.CA, "Generates a root certificate. Use this to establish a chain of trust with derived certificates.")
	fs.IntVar(&args.MaxPathLen, "max-path-len", args.MaxPathLen, "How many CAs may sit below the CA made by --ca or --yubikey-generate-root: 0 lets it sign only leaf certificates. -1 means no limit.")
	fs.StringVar(&args.PermittedDNSDomains, "permitted-dns-domains", args.PermittedDNSDomains, "Comma-separated DNS domains that certificates below the CA may use, as critical name constraints: example.com permits it and its subdomains, .example.com only its subdomains.")
	fs.StringVar(&args.PermittedIPRanges, "permitted-ip-ranges", args.PermittedIPRanges, "Comma-separated IP ranges in CIDR notation (10.0.0.0/8) that certificates below the CA may use, as critical name constraints.")

	fs.StringVar(&args.CommonName, "common-name", args.CommonName, "Common Name (CN) field of the X.509 certificate subject. Defaults to the --organization value.")
	fs.StringVar(&args.Country, "country", args.Country, "Country (C) field of the X.509 certificate subject (e.g. US, CA, GB).")
	fs.StringVar(&args.Organization, "organization", args.Organization, "Organization (O) field of the X.509 certificate subject.")
	fs.StringVar(&args.OrganizationalUnit, "organizational-unit", args.OrganizationalUnit, "Organizational Unit (OU) field of the X.509 certificate subject.")
	fs.StringVar(&args.Locality, "locality", args.Locality, "Locality (L) field of the X.509 certificate subject, typically the city name.")
	fs.StringVar(&args.Province, "province", args.Province, "Province or state (ST) field of the X.509 certificate subject.")

	fs.DurationVar(&args.Validity, "validity", args.Validity, "How long the certificate is valid for, as a Go duration (e.g. 8760h, 720h, 24h).")
	fs.StringVar(&args.Hostnames, "hostnames", args.Hostnames, "Comma-separated list of hostnames and IP addresses to include as Subject Alternative Names (SANs). A wildcard must be the leftmost label of a name with at least two more labels (*.example.com); ports are removed.")
	fs.StringVar(&args.KeyType, "key-type", args.KeyType, "Key algorithm and length: RSA-2048, RSA-4096, ECDSA-224, ECDSA-256, ECDSA-384, or ECDSA-521. Defaults to RSA-2048, or to the --target profile's key type with --code-sign.")

	fs.StringVar(&args.ParentPublicCertificate, "parent-public-certificate", args.ParentPublicCertificate, "(optional) Parent public certificate. If set, the output certificate will trust the parent. Requires --parent-private-key.")
	fs.StringVar(&args.ParentPrivateKey, "parent-private-key", args.ParentPrivateKey, "(optional) Private key of --parent-public-certificate, used to sign the output certificate.")

	fs.BoolVar(&args.CodeSigning, "code-sign", args.CodeSigning, "Generates a code signing certificate for binary signing instead of a TLS certificate.")
	fs.StringVar(&args.Target, "target", args.Target, "Platform profile for --code-sign. Values: windows7 (win7/windows8/win8), windows10 (win10), windows11 (win11), linux. Default: windows10.")
	fs.StringVar(&args.PFXOutput, "pfx-output", args.PFXOutput, "Output path for the PKCS#12 (.pfx) file. Used with --code-sign for Windows targets.")
	fs.StringVar(&args.PFXPassword, "pfx-password", args.PFXPassword, "Password for the PKCS#12 (.pfx) file. Defaults to the "+certtool.PFXPasswordEnv+" environment variable, which keeps it off the command line. Empty means no password.")

	fs.StringVar(&args.Spec, "spec", args.Spec, "Path to a YAML file specifying certificates to generate. See CertificateSpec for the format.")
	fs.StringVar(&args.Chain, "chain", args.Chain, "Generate a certificate hierarchy from the number of certificates per layer. A single number produces that many standalone leaf certificates (e.g. 3). Comma-separated numbers set the width of each layer from the root down, the last being the leaves (e.g. 1,1 = root CA and leaf; 1,2,3 = 1 root, 2 intermediates per root, 3 leaves per intermediate).")
	fs.StringVar(&args.NamePrefix, "name-prefix", args.NamePrefix, "Prefix placed in front of the common name of every certificate generated by --chain (e.g. prod). Empty by default.")
	fs.StringVar(&args.OutputDir, "output-dir", args.OutputDir, "Output directory for certificates generated by --spec or --chain.")
	fs.BoolVar(&args.Overwrite, "overwrite", args.Overwrite, "With --spec or --chain, regenerate every certificate and key and replace the files in --output-dir. By default certificates whose .crt and .key already exist there are reused, so a spec can be extended without resetting its hierarchy.")
	fs.StringVar(&args.ExportSpec, "export-spec", args.ExportSpec, "Export the certificate spec as a YAML file instead of generating certificates. Works with --chain or flag-based mode.")

	fs.BoolVar(&args.YubiKey, "yubikey", args.YubiKey, "Sign with the root CA stored on a YubiKey instead of --parent-public-certificate/--parent-private-key. Applies to single certificates, --chain, and --spec, whose top-level certificates are signed by the YubiKey. Requires the PIN.")
	fs.BoolVar(&args.YubiKeyGenerateRoot, "yubikey-generate-root", args.YubiKeyGenerateRoot, "Generate a root CA key on a YubiKey and store its self-signed certificate there. The public certificate is also written to --public-certificate; the private key never leaves the YubiKey. Uses the subject, --validity, and --key-type flags (ECDSA-256, ECDSA-384, RSA-2048, or RSA-4096). Requires the PIN.")
	fs.StringVar(&args.YubiKeySerial, "yubikey-serial", args.YubiKeySerial, "Serial number of the YubiKey to use. Required only when more than one YubiKey is connected.")
	fs.StringVar(&args.YubiKeySlot, "yubikey-slot", args.YubiKeySlot, "PIV slot holding the YubiKey root CA: 9a, 9c, 9d, 9e, or 82 through 95.")
	fs.StringVar(&args.YubiKeyPIN, "yubikey-pin", args.YubiKeyPIN, "YubiKey PIN, required by --yubikey and --yubikey-generate-root. Defaults to the "+certtool.YubiKeyPINEnv+" environment variable. certtool never prompts for it.")
	fs.StringVar(&args.YubiKeyManagementKey, "yubikey-management-key", args.YubiKeyManagementKey, "YubiKey management key in hex, needed by --yubikey-generate-root. Defaults to the "+certtool.YubiKeyManagementKeyEnv+" environment variable, otherwise the PIN-protected management key or the factory default.")
	fs.StringVar(&args.YubiKeyTouchPolicy, "yubikey-touch-policy", args.YubiKeyTouchPolicy, "Whether the YubiKey must be touched to sign with a key made by --yubikey-generate-root: always (the default, a touch for every signature), cached (one touch allows signing for 15 seconds), or never.")
	fs.BoolVar(&args.YubiKeyOverwrite, "yubikey-overwrite", args.YubiKeyOverwrite, "Allow --yubikey-generate-root to replace a slot that already holds a certificate. The old key is destroyed.")

	fs.BoolVar(&args.Version, "version", args.Version, "Print version and build information, then exit.")

	err := fs.Parse(arguments)
	return args, err
}
