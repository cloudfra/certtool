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

// Package certtool implements the certtool command. The main package parses
// the command line flags into Args and calls Run.
//
// certtool runs unattended in automation, so it never prompts for input.
// Missing or invalid options fail with an error that names the flag.
package certtool

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/cloudfra/certtool/internal"
	"github.com/cloudfra/certtool/internal/safefile"
	certlib "github.com/cloudfra/certtool/pkg/certtool"
	"github.com/cloudfra/certtool/pkg/yubikey"
)

const (
	algorithmRSA          = "RSA"
	algorithmECDSA        = "ECDSA"
	defaultCodeSignTarget = "windows10"

	// YubiKeyPINEnv is read when Args.YubiKeyPIN is empty.
	YubiKeyPINEnv = "CERTTOOL_YUBIKEY_PIN"
	// YubiKeyManagementKeyEnv is read when Args.YubiKeyManagementKey is empty.
	YubiKeyManagementKeyEnv = "CERTTOOL_YUBIKEY_MANAGEMENT_KEY"
	// PFXPasswordEnv is read when Args.PFXPassword is empty.
	PFXPasswordEnv = "CERTTOOL_PFX_PASSWORD" //nolint:gosec // The name of an environment variable, not a credential.
)

// Args holds the certtool command line options, one field per flag. Comma
// separated lists are kept as they were given on the command line.
type Args struct {
	// PublicCertificate is --public-certificate.
	PublicCertificate string
	// PrivateKey is --private-key.
	PrivateKey string
	// CA is --ca.
	CA bool

	// CommonName is --common-name. Empty uses Organization.
	CommonName string
	// Country is --country.
	Country string
	// Organization is --organization.
	Organization string
	// OrganizationalUnit is --organizational-unit.
	OrganizationalUnit string
	// Locality is --locality.
	Locality string
	// Province is --province.
	Province string

	// Validity is --validity.
	Validity time.Duration
	// Hostnames is --hostnames, comma separated.
	Hostnames string
	// KeyType is --key-type. Empty selects RSA-2048, or the key type of the
	// --target profile with --code-sign.
	KeyType string

	// ParentPublicCertificate is --parent-public-certificate.
	ParentPublicCertificate string
	// ParentPrivateKey is --parent-private-key.
	ParentPrivateKey string

	// CodeSigning is --code-sign.
	CodeSigning bool
	// Target is --target.
	Target string
	// PFXOutput is --pfx-output.
	PFXOutput string
	// PFXPassword is --pfx-password. When empty, the PFXPasswordEnv
	// environment variable is used.
	PFXPassword string

	// Spec is --spec.
	Spec string
	// Chain is --chain, comma separated.
	Chain string
	// NamePrefix is --name-prefix.
	NamePrefix string
	// OutputDir is --output-dir.
	OutputDir string
	// ExportSpec is --export-spec.
	ExportSpec string

	// YubiKey is --yubikey.
	YubiKey bool
	// YubiKeyGenerateRoot is --yubikey-generate-root.
	YubiKeyGenerateRoot bool
	// YubiKeySerial is --yubikey-serial.
	YubiKeySerial string
	// YubiKeySlot is --yubikey-slot.
	YubiKeySlot string
	// YubiKeyPIN is --yubikey-pin. Empty uses the CERTTOOL_YUBIKEY_PIN
	// environment variable.
	YubiKeyPIN string
	// YubiKeyManagementKey is --yubikey-management-key. Empty uses the
	// CERTTOOL_YUBIKEY_MANAGEMENT_KEY environment variable.
	YubiKeyManagementKey string
	// YubiKeyTouchPolicy is --yubikey-touch-policy.
	YubiKeyTouchPolicy string
	// YubiKeyOverwrite is --yubikey-overwrite.
	YubiKeyOverwrite bool

	// Version is --version.
	Version bool
}

// DefaultArgs returns the default value of every option.
func DefaultArgs() Args {
	return Args{
		PublicCertificate:  "app.crt",
		PrivateKey:         "app.key",
		Country:            "US",
		Organization:       "cloudfra",
		OrganizationalUnit: "gows",
		Locality:           "Seattle",
		Province:           "WA",
		Validity:           365 * 24 * time.Hour,
		PFXOutput:          "codesign.pfx",
		OutputDir:          ".",
		YubiKeySlot:        yubikey.DefaultSlot,
		YubiKeyTouchPolicy: string(yubikey.DefaultTouchPolicy),
	}
}

// Run runs certtool with args.
func Run(args Args) error {
	if args.Version {
		fmt.Printf("certtool %s (built %s)\n", internal.Version(), internal.Buildstamp())
		return nil
	}

	if args.Target != "" && !args.CodeSigning {
		slog.Warn("--target is set but --code-sign is not; --target will be ignored")
	}
	if args.NamePrefix != "" && args.Chain == "" {
		slog.Warn("--name-prefix is set but --chain is not; --name-prefix will be ignored")
	}

	if err := validateModes(args); err != nil {
		return err
	}

	if args.YubiKeyGenerateRoot {
		return runYubiKeyGenerateRoot(args)
	}

	if args.ExportSpec != "" && args.YubiKey {
		slog.Warn("--yubikey is set with --export-spec; the exported spec does not record the YubiKey issuer")
	}

	var issuer *certlib.Issuer
	if args.YubiKey && args.ExportSpec == "" {
		token, err := openYubiKey(args)
		if err != nil {
			return err
		}
		defer closeYubiKey(token)

		issuer, err = token.Issuer()
		if err != nil {
			return err
		}
		slog.Info("signing with YubiKey root CA", "serial", token.Serial(), "slot", args.YubiKeySlot, "cn", issuer.Certificate.Subject.CommonName)
		warnFactoryDefaults(token)
	}

	switch {
	case args.Spec != "":
		return runSpec(args, issuer)
	case args.Chain != "":
		return runChain(args, issuer)
	case args.ExportSpec != "":
		return runExportSpec(args)
	}

	certArgs, err := certificateArgs(args)
	if err != nil {
		return err
	}
	certArgs.Issuer = issuer
	return generateAndWriteKeyPair(args, certArgs)
}

func validateModes(args Args) error {
	defaults := DefaultArgs()
	hasChain := args.Chain != ""
	hasSpec := args.Spec != ""
	if hasChain && hasSpec {
		return errors.New("--chain and --spec are mutually exclusive")
	}
	if args.YubiKey && args.YubiKeyGenerateRoot {
		return errors.New("--yubikey and --yubikey-generate-root are mutually exclusive")
	}
	if args.YubiKey && (args.ParentPublicCertificate != "" || args.ParentPrivateKey != "") {
		return errors.New("--yubikey and --parent-public-certificate/--parent-private-key are mutually exclusive")
	}
	if args.YubiKeyGenerateRoot && (hasChain || hasSpec || args.ExportSpec != "" || args.CodeSigning || args.ParentPublicCertificate != "" || args.ParentPrivateKey != "") {
		return errors.New("--yubikey-generate-root cannot be combined with --chain, --spec, --export-spec, --code-sign, or --parent-public-certificate/--parent-private-key")
	}
	if !args.YubiKeyGenerateRoot && (args.YubiKeyOverwrite || args.YubiKeyTouchPolicy != defaults.YubiKeyTouchPolicy) {
		return errors.New("--yubikey-touch-policy and --yubikey-overwrite only apply to --yubikey-generate-root")
	}
	if !args.YubiKey && !args.YubiKeyGenerateRoot && (args.YubiKeySerial != "" || args.YubiKeySlot != defaults.YubiKeySlot || args.YubiKeyPIN != "" || args.YubiKeyManagementKey != "") {
		return errors.New("the --yubikey-* options need --yubikey or --yubikey-generate-root")
	}
	if args.ParentPublicCertificate != "" && args.ParentPrivateKey == "" {
		return errors.New("--parent-private-key is required with --parent-public-certificate, to sign with the parent certificate's key")
	}
	if args.ParentPrivateKey != "" && args.ParentPublicCertificate == "" {
		return errors.New("--parent-public-certificate is required with --parent-private-key, to name the issuer of the new certificate")
	}
	return nil
}

// openYubiKey opens the YubiKey selected by the --yubikey-* options.
func openYubiKey(args Args) (*yubikey.Token, error) {
	cfg, err := yubiKeyConfig(args)
	if err != nil {
		return nil, err
	}
	return yubikey.Open(cfg)
}

// yubiKeyConfig builds the YubiKey configuration from the --yubikey-*
// options, falling back to environment variables for the secrets. The PIN is
// required because certtool never prompts for it.
func yubiKeyConfig(args Args) (yubikey.Config, error) {
	pin := args.YubiKeyPIN
	if pin == "" {
		pin = os.Getenv(YubiKeyPINEnv)
	}
	if pin == "" {
		mode := "--yubikey"
		if args.YubiKeyGenerateRoot {
			mode = "--yubikey-generate-root"
		}
		return yubikey.Config{}, fmt.Errorf("%s needs the YubiKey PIN to sign with the key on the YubiKey: set --yubikey-pin or the %s environment variable", mode, YubiKeyPINEnv)
	}
	managementKey := args.YubiKeyManagementKey
	if managementKey == "" {
		managementKey = os.Getenv(YubiKeyManagementKeyEnv)
	}

	var serial uint64
	if args.YubiKeySerial != "" {
		var err error
		if serial, err = strconv.ParseUint(args.YubiKeySerial, 10, 32); err != nil {
			return yubikey.Config{}, fmt.Errorf("--yubikey-serial %q is not a valid serial number", args.YubiKeySerial)
		}
	}

	return yubikey.Config{
		Serial:        uint32(serial),
		Slot:          args.YubiKeySlot,
		PIN:           pin,
		ManagementKey: managementKey,
		BeforeSign: func() {
			slog.Info("signing with the YubiKey, touch it if it is blinking")
		},
	}, nil
}

func closeYubiKey(token *yubikey.Token) {
	if err := token.Close(); err != nil {
		slog.Warn("cannot close the YubiKey", "error", err)
	}
}

func runYubiKeyGenerateRoot(args Args) error {
	touchPolicy, err := yubikey.ParseTouchPolicy(args.YubiKeyTouchPolicy)
	if err != nil {
		return err
	}

	certArgs, err := certificateArgs(args)
	if err != nil {
		return err
	}

	token, err := openYubiKey(args)
	if err != nil {
		return err
	}
	defer closeYubiKey(token)

	slog.Info("generating root CA on YubiKey", "serial", token.Serial(), "slot", args.YubiKeySlot)
	cert, err := token.GenerateRoot(certArgs, touchPolicy, args.YubiKeyOverwrite)
	if err != nil {
		return err
	}

	if err := certlib.WriteCertificate(cert, args.PublicCertificate); err != nil {
		return err
	}
	slog.Info("generated YubiKey root CA", "cn", cert.Subject.CommonName, "cert", args.PublicCertificate, "serial", token.Serial(), "slot", args.YubiKeySlot)
	warnFactoryDefaults(token)
	return nil
}

// warnFactoryDefaults warns when the YubiKey still uses factory default
// credentials, which let anyone holding it use or replace the root CA key.
func warnFactoryDefaults(token *yubikey.Token) {
	defaults := token.FactoryDefaults()
	if len(defaults) == 0 {
		return
	}
	slog.Warn("the YubiKey still uses its factory default "+strings.Join(defaults, " and ")+", so anyone holding it can use or replace the root CA key; change them with `ykman piv access change-pin`, `ykman piv access change-puk`, and `ykman piv access change-management-key --generate --protect`", "serial", token.Serial())
}

func parseChain(chain string) ([]int, error) {
	parts := strings.Split(chain, ",")
	widths := make([]int, len(parts))
	for i, p := range parts {
		p = strings.TrimSpace(p)
		v, err := strconv.Atoi(p)
		if err != nil {
			return nil, fmt.Errorf("--chain value %q is not a valid integer", p)
		}
		widths[i] = v
	}
	return widths, nil
}

func runChain(args Args, issuer *certlib.Issuer) error {
	widths, err := parseChain(args.Chain)
	if err != nil {
		return err
	}

	specs, err := certlib.ChainToSpec(widths, args.CommonName, args.Organization, args.NamePrefix)
	if err != nil {
		return err
	}

	if args.ExportSpec != "" {
		return writeSpecFile(specs, args.ExportSpec)
	}
	return generateAndLogResults(specs, args.OutputDir, issuer)
}

// pfxPassword returns --pfx-password, or the PFXPasswordEnv environment
// variable when the flag is empty.
func pfxPassword(args Args) string {
	if args.PFXPassword != "" {
		return args.PFXPassword
	}
	return os.Getenv(PFXPasswordEnv)
}

func runExportSpec(args Args) error {
	specs, err := argsToSpec(args)
	if err != nil {
		return err
	}
	return writeSpecFile(specs, args.ExportSpec)
}

func argsToSpec(args Args) ([]certlib.CertificateSpec, error) {
	hostnames, err := splitHostnames(args.Hostnames)
	if err != nil {
		return nil, err
	}

	cn := args.CommonName
	if cn == "" {
		cn = args.Organization
	}

	s := certlib.CertificateSpec{
		CommonName:           cn,
		CertificateAuthority: args.CA,
		CodeSigning:          args.CodeSigning,
		Target:               args.Target,
		KeyType:              args.KeyType,
		Validity:             args.Validity.String(),
		Organization:         args.Organization,
		OrganizationalUnit:   args.OrganizationalUnit,
		Country:              args.Country,
		Locality:             args.Locality,
		Province:             args.Province,
		Hostnames:            hostnames,
	}
	if s.KeyType == "" && !s.CodeSigning {
		s.KeyType = "RSA-2048"
	}
	if pfxPassword(args) != "" {
		// Never write the password itself into the spec file.
		s.PFXPasswordEnv = PFXPasswordEnv
		slog.Warn("the exported spec reads the .pfx password from the environment instead of storing it", "env", PFXPasswordEnv)
	}
	return []certlib.CertificateSpec{s}, nil
}

func writeSpecFile(specs []certlib.CertificateSpec, path string) error {
	data, err := certlib.MarshalSpec(specs)
	if err != nil {
		return err
	}
	if err := safefile.WritePrivate(filepath.Clean(path), data); err != nil {
		return err
	}
	slog.Info("spec written", "path", path)
	return nil
}

func generateAndLogResults(specs []certlib.CertificateSpec, outputDir string, issuer *certlib.Issuer) error {
	results, err := certlib.GenerateFromSpecWithIssuer(specs, outputDir, issuer)
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

func runSpec(args Args, issuer *certlib.Issuer) error {
	specs, err := certlib.ReadSpec(args.Spec)
	if err != nil {
		return err
	}

	if names := certlib.SpecsWithPFXPassword(specs); len(names) > 0 {
		slog.Warn("the spec stores .pfx passwords in plain text; use pfxPasswordEnv to read them from the environment instead", "specs", names)
	}

	if names := certlib.SpecsWithUnprotectedPFX(specs); len(names) > 0 && args.ExportSpec == "" {
		slog.Warn("these specs make a .pfx without a password, so anyone who can read it can sign code with its key; set pfxPasswordEnv", "specs", names)
	}

	if args.ExportSpec != "" {
		if names := certlib.SpecsWithPFXPassword(specs); len(names) > 0 {
			certlib.ReplacePFXPasswords(specs, PFXPasswordEnv)
			slog.Warn("the exported spec reads the .pfx passwords from the environment instead of storing them", "env", PFXPasswordEnv, "specs", names)
		}
		return writeSpecFile(specs, args.ExportSpec)
	}
	return generateAndLogResults(specs, args.OutputDir, issuer)
}

func generateAndWriteKeyPair(args Args, certArgs *certlib.Args) error {
	kp, err := certlib.GenerateKeyPair(certArgs)
	if err != nil {
		return err
	}
	if len(kp.PFX) > 0 {
		if certArgs.PFXPassword == "" {
			slog.Warn("the .pfx has no password, so anyone who can read it can sign code with its key; set "+PFXPasswordEnv+" or --pfx-password", "pfx", args.PFXOutput)
		}
		return certlib.WritePFX(kp, args.PFXOutput)
	}
	return certlib.WriteKeyPair(kp, args.PublicCertificate, args.PrivateKey)
}

// certificateArgs converts the options to the arguments of a single
// certificate.
func certificateArgs(args Args) (*certlib.Args, error) {
	var kt *certlib.KeyType
	if args.KeyType != "" || !args.CodeSigning {
		algorithm, keyLength, err := stringToKeyType(args.KeyType)
		if err != nil {
			return nil, err
		}
		kt = &certlib.KeyType{Algorithm: algorithm, KeyLength: keyLength}

		// Warn if the user explicitly chose ECDSA for a Windows 7 target.
		if args.CodeSigning && strings.ToUpper(algorithm) == algorithmECDSA {
			effectiveTarget := args.Target
			if effectiveTarget == "" {
				effectiveTarget = defaultCodeSignTarget
			}
			if profile, profErr := certlib.GetProfile(effectiveTarget); profErr == nil && profile.LegacyPFX {
				slog.Warn("ECDSA code signing certs are not supported by Windows 7 signtool.exe; proceeding with user-specified key type")
			}
		}
	}
	// If kt is nil and CodeSigning is set, the key type comes from the profile.

	var parent *certlib.KeyPair
	if args.ParentPublicCertificate != "" {
		var err error
		parent, err = certlib.ReadKeyPairFromFile(args.ParentPublicCertificate, args.ParentPrivateKey)
		if err != nil {
			return nil, err
		}
	}

	if args.Validity <= 0 {
		return nil, fmt.Errorf("--validity must be a positive duration, got %s", args.Validity)
	}

	hostnames, err := splitHostnames(args.Hostnames)
	if err != nil {
		return nil, err
	}
	return &certlib.Args{
		CA:                 args.CA,
		CommonName:         args.CommonName,
		Country:            args.Country,
		Organization:       args.Organization,
		OrganizationalUnit: args.OrganizationalUnit,
		Locality:           args.Locality,
		Province:           args.Province,
		Validity:           args.Validity,
		Hostnames:          hostnames,
		KeyType:            kt,
		ParentKeyPair:      parent,
		CodeSigning:        args.CodeSigning,
		Target:             args.Target,
		PFXPassword:        pfxPassword(args),
	}, nil
}

func stringToKeyType(keyType string) (string, int, error) {
	if keyType == "" {
		return algorithmRSA, 2048, nil
	}
	switch parseKeyTypeKeyName(keyType) {
	case algorithmRSA:
		return parseKeyTypeName(keyType, 2048, []int{2048, 4096})
	case algorithmECDSA:
		return parseKeyTypeName(keyType, 521, []int{224, 256, 384, 521})
	}
	return "", 0, fmt.Errorf("--key-type '%s' is not a valid key type", keyType)
}

func parseKeyTypeKeyName(keyTypeName string) string {
	parts := strings.Split(strings.ToUpper(keyTypeName), "-")
	if len(parts) > 0 {
		return parts[0]
	}
	return algorithmRSA
}

func parseKeyTypeName(keyTypeName string, defaultLength int, validValues []int) (string, int, error) {
	parts := strings.Split(strings.ToUpper(keyTypeName), "-")
	if len(parts) > 2 {
		return "", 0, fmt.Errorf("--key-type '%s' is not valid", keyTypeName)
	}
	if len(parts) == 0 {
		return "", 0, errors.New("--key-type does not have a name")
	}

	algorithm := parts[0]
	keyLength := ""
	if len(parts) == 2 {
		keyLength = parts[1]
	}

	if keyLength == "" {
		return algorithm, defaultLength, nil
	}
	length, err := strconv.Atoi(parts[1])
	if err != nil {
		return "", 0, fmt.Errorf("--key-type '%s' does not have a valid %s key length", keyTypeName, algorithm)
	}
	if slices.Contains(validValues, length) {
		return algorithm, length, nil
	}

	return "", 0, fmt.Errorf("--key-type '%s' does not have a valid %s key length", keyTypeName, algorithm)
}

func splitStrings(csv string) []string {
	if csv == "" {
		return nil
	}
	parts := strings.Split(csv, ",")
	for i, p := range parts {
		parts[i] = strings.TrimSpace(p)
	}
	return parts
}

// splitHostnames splits the --hostnames list and checks that each entry can be
// a certificate name.
func splitHostnames(csv string) ([]string, error) {
	hostnames := splitStrings(csv)
	for _, hostname := range hostnames {
		if err := certlib.ValidateHostname(hostname); err != nil {
			return nil, fmt.Errorf("--hostnames: %w", err)
		}
	}
	return hostnames, nil
}
