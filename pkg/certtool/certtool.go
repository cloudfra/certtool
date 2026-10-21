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

// Package certtool is the public interface for integrating with auto generating certificates.
package certtool

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"
)

const (
	oneYear                          = time.Hour * 24 * 365
	rsaPrivateKeyPEMType             = "RSA PRIVATE KEY"
	ecPrivateKeyPEMType              = "EC PRIVATE KEY"
	numDistinguishedNameSegmentParts = 2
	subjectDelimiter                 = "/"
	partDelimiter                    = "="
	subjectDelimiterReplacement      = "\u2318"
	ecdsaAlgorithm                   = "ECDSA"
	rsaAlgorithm                     = "RSA"
	defaultOrganization              = "Certtool"
)

// Args of creating a self-signed X.509 public certificate/private key pair.
type Args struct {
	// CA indicates we need to create a CA certificate.
	CA bool

	// CommonName of the entity representing the certificate. Defaults to the Organization value when empty.
	CommonName string
	// Country of the entity representing the certificate.
	Country string
	// Organization of the entity representing the certificate.
	Organization string
	// OrganizationalUnit of the entity representing the certificate.
	OrganizationalUnit string
	// Locality of the entity representing the certificate.
	Locality string
	// Province (or state) of the entity representing the certificate.
	Province string

	// Hostnames are the DNS names and IP addresses the certificate is for. A
	// port on a hostname ("a.com:443") is removed, because certificate names
	// cannot hold ports.
	Hostnames []string
	// Validity is how long the certificate should be valid for.
	Validity time.Duration
	// ParentKeyPair is the root public certificate within the chain of trust.
	ParentKeyPair *KeyPair
	// Issuer signs the certificate with a CA key held outside of certtool,
	// such as on a YubiKey. Mutually exclusive with ParentKeyPair.
	Issuer *Issuer

	// KeyType is the type of key to generate.
	KeyType *KeyType

	// CodeSigning generates a code signing certificate instead of a TLS certificate.
	// When true, ExtKeyUsageCodeSigning is set, KeyEncipherment is removed, and no
	// auto-SANs (localhost/127.0.0.1) are added.
	CodeSigning bool
	// Target selects a named platform profile when CodeSigning is true.
	// Valid values: windows7, windows10, windows11, linux (and aliases).
	// Defaults to "windows10" when empty and CodeSigning is true.
	Target string
	// PFXPassword is the password for PKCS#12 output. Empty string = no password.
	PFXPassword string
}

// GetKeyType returns the KeyType from the Args, or a default if nil.
func (args *Args) GetKeyType() *KeyType {
	if args == nil || args.KeyType == nil {
		return defaultKeyType()
	}

	return args.KeyType
}

// GetHostnames returns the hostnames with any port removed and duplicates
// dropped, in sorted order.
func (args *Args) GetHostnames() []string {
	seen := map[string]bool{}
	all := []string{}
	for _, hostname := range args.Hostnames {
		host := hostWithoutPort(strings.TrimSpace(hostname))
		if host != "" && !seen[host] {
			seen[host] = true
			all = append(all, host)
		}
	}
	sort.Strings(all)
	return all
}

// hostWithoutPort returns hostname without a trailing port, so "a.com:443"
// and "[::1]:443" become "a.com" and "::1". X.509 names cannot hold ports.
func hostWithoutPort(hostname string) string {
	if host, _, err := net.SplitHostPort(hostname); err == nil {
		return host
	}
	return hostname
}

// ValidateHostname returns an error unless hostname, with any port removed, is
// an IP address or a DNS name that can be a certificate's subject alternative
// name. A wildcard is allowed only as the whole leftmost label of a name with
// at least two more labels, such as *.example.com.
func ValidateHostname(hostname string) error {
	host := hostWithoutPort(strings.TrimSpace(hostname))
	if net.ParseIP(host) != nil {
		return nil
	}
	if err := validateDNSName(host); err != nil {
		return fmt.Errorf("hostname %q is not a valid DNS name or IP address: %w", hostname, err)
	}
	return nil
}

const (
	maxDNSNameLength  = 253
	maxDNSLabelLength = 63
)

func validateDNSName(name string) error {
	name = strings.TrimSuffix(name, ".")
	switch {
	case name == "":
		return fmt.Errorf("it is empty")
	case len(name) > maxDNSNameLength:
		return fmt.Errorf("it is longer than %d characters", maxDNSNameLength)
	}

	labels := strings.Split(name, ".")
	for i, label := range labels {
		if label == "*" && i == 0 {
			if len(labels) < 3 {
				return fmt.Errorf("a wildcard needs at least two labels after it, such as *.example.com")
			}
			continue
		}
		if err := validateDNSLabel(label); err != nil {
			return err
		}
	}
	return nil
}

func validateDNSLabel(label string) error {
	switch {
	case label == "":
		return fmt.Errorf("it has an empty label")
	case len(label) > maxDNSLabelLength:
		return fmt.Errorf("the label %q is longer than %d characters", label, maxDNSLabelLength)
	case strings.Contains(label, "*"):
		return fmt.Errorf("a wildcard must be the whole leftmost label, such as *.example.com")
	case label[0] == '-' || label[len(label)-1] == '-':
		return fmt.Errorf("the label %q starts or ends with a hyphen", label)
	}
	for _, r := range label {
		ok := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_'
		if !ok {
			return fmt.Errorf("the label %q has the character %q; use letters, digits, and hyphens, and punycode (xn--) for international names", label, r)
		}
	}
	return nil
}

// subjectAltNames returns the DNS names and IP addresses for hostnames, with
// ports removed and duplicates dropped, each in sorted order.
func subjectAltNames(hostnames []string) ([]string, []net.IP, error) {
	var dnsNames []string
	var ips []net.IP
	seen := map[string]bool{}
	for _, hostname := range hostnames {
		if strings.TrimSpace(hostname) == "" {
			continue
		}
		if err := ValidateHostname(hostname); err != nil {
			return nil, nil, err
		}
		host := strings.TrimSuffix(hostWithoutPort(strings.TrimSpace(hostname)), ".")
		if ip := net.ParseIP(host); ip != nil {
			if !seen[ip.String()] {
				seen[ip.String()] = true
				ips = append(ips, ip)
			}
			continue
		}
		if key := strings.ToLower(host); !seen[key] {
			seen[key] = true
			dnsNames = append(dnsNames, host)
		}
	}
	sort.Strings(dnsNames)
	sort.Slice(ips, func(i, j int) bool { return ips[i].String() < ips[j].String() })
	return dnsNames, ips, nil
}

// KeyType is the key descriptor.
type KeyType struct {
	// Algorithm of the encryption
	Algorithm string
	// KeyLength is the length in bytes of the key.
	KeyLength int
}

// Issuer is a certificate authority whose private key is held outside of
// certtool, such as on a hardware security token. Certificates generated with
// an Issuer are signed by Signer and chain to Certificate.
type Issuer struct {
	// Certificate is the public certificate of the issuing CA.
	Certificate *x509.Certificate
	// Signer signs with the private key of the issuing CA.
	Signer crypto.Signer
}

// KeyPair is the X.509 public certificate/private key pair
type KeyPair struct {
	// PublicCertificate of the X.509 key pair.
	PublicCertificate []byte
	// PrivateKey of the X.509 key pair.
	PrivateKey []byte
	// PFX is the PKCS#12 bundle. Populated for Windows targets when CodeSigning is true.
	PFX []byte
}

func fillDefaults(args *Args) {
	if args.Country == "" {
		args.Country = "US"
	}
	if args.Organization == "" {
		args.Organization = defaultOrganization
	}
	if args.CommonName == "" {
		args.CommonName = args.Organization
	}
	if args.OrganizationalUnit == "" {
		args.OrganizationalUnit = "None"
	}
	if args.Locality == "" {
		args.Locality = "Seattle"
	}
	if args.Province == "" {
		args.Province = "WA"
	}
	if args.Validity == 0 {
		args.Validity = oneYear
	}
	if args.CodeSigning {
		if args.Target == "" {
			args.Target = windows10Target
		}
		if args.KeyType == nil {
			if profile, err := GetProfile(args.Target); err == nil {
				args.KeyType = &KeyType{
					Algorithm: profile.KeyType.Algorithm,
					KeyLength: profile.KeyType.KeyLength,
				}
			}
		}
	}
	if args.KeyType == nil {
		args.KeyType = defaultKeyType()
	}
}

func defaultKeyType() *KeyType {
	return &KeyType{
		Algorithm: rsaAlgorithm,
		KeyLength: 2048,
	}
}

// GenerateKeyPair generates a new X.509 public certificate/private key pair.
func GenerateKeyPair(args *Args) (*KeyPair, error) {
	fillDefaults(args)

	return createCertificateAndPrivateKeyPEM(args)
}

func createCertificateAndPrivateKeyPEM(args *Args) (*KeyPair, error) {
	// Validate target early if code signing, before any expensive crypto work
	if args.CodeSigning {
		if _, err := GetProfile(args.Target); err != nil {
			return nil, err
		}
	}

	keyType := args.GetKeyType()
	switch strings.ToUpper(keyType.Algorithm) {
	case rsaAlgorithm, ecdsaAlgorithm:
	default:
		return nil, fmt.Errorf("key algorithm, %s, is not valid", keyType.Algorithm)
	}

	privateKey, err := generatePrivateKeyFromType(*keyType)
	if err != nil {
		return nil, fmt.Errorf("cannot generate private key, %w", err)
	}

	pubKey, err := publicKey(privateKey)
	if err != nil {
		return nil, err
	}

	certTemplate, err := newCertificateTemplate(args, pubKey)
	if err != nil {
		return nil, err
	}

	var parentSigner crypto.Signer
	parentTemplate := certTemplate

	if args.Issuer != nil && args.ParentKeyPair != nil {
		return nil, fmt.Errorf("issuer and parent key pair are mutually exclusive")
	}

	if args.Issuer != nil {
		if args.Issuer.Certificate == nil || args.Issuer.Signer == nil {
			return nil, fmt.Errorf("issuer must have both a certificate and a signer")
		}
		parentTemplate = args.Issuer.Certificate
		parentSigner = args.Issuer.Signer
	}

	if args.ParentKeyPair != nil {
		hasPublicCertificate := len(args.ParentKeyPair.PublicCertificate) > 0
		hasPrivateKey := len(args.ParentKeyPair.PrivateKey) > 0
		switch {
		case hasPublicCertificate && !hasPrivateKey:
			return nil, fmt.Errorf("root public certificate data was set but root private key data was not")
		case !hasPublicCertificate && hasPrivateKey:
			return nil, fmt.Errorf("root private key data was set but root public certificate data was not")
		case hasPublicCertificate && hasPrivateKey:
			parentPublicCertificateT, parentPrivateKeyT, readErr := ReadKeyPair(args.ParentKeyPair.PublicCertificate, args.ParentKeyPair.PrivateKey)
			if readErr != nil {
				return nil, readErr
			}
			signer, ok := parentPrivateKeyT.(crypto.Signer)
			if !ok {
				return nil, fmt.Errorf("parent private key of type %T cannot sign certificates", parentPrivateKeyT)
			}
			parentTemplate = parentPublicCertificateT
			parentSigner = signer
		}
	}

	if parentSigner == nil {
		parentSigner, _ = privateKey.(crypto.Signer)
	} else {
		if err := checkIssuer(parentTemplate, certTemplate, time.Now()); err != nil {
			return nil, err
		}
		// A certificate is only valid while its issuer is, so it must not
		// claim to outlive it.
		if certTemplate.NotAfter.After(parentTemplate.NotAfter) {
			certTemplate.NotAfter = parentTemplate.NotAfter
		}
	}

	// The signature algorithm must match the key that signs the certificate,
	// which is the parent's key unless the certificate is self-signed.
	certTemplate.SignatureAlgorithm, err = signatureAlgorithm(parentSigner.Public(), args.CodeSigning)
	if err != nil {
		return nil, err
	}

	cert, err := x509.CreateCertificate(rand.Reader, certTemplate, parentTemplate, pubKey, parentSigner)
	if err != nil {
		return nil, fmt.Errorf("cannot create X.509 public certificate, %w", err)
	}

	publicCertificatePemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert,
	})

	pemPrivateKey, err := pemBlockForKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("cannot create PEM block for private key, %w", err)
	}

	privateKeyPemBytes := pem.EncodeToMemory(pemPrivateKey)

	kp := &KeyPair{
		PublicCertificate: publicCertificatePemBytes,
		PrivateKey:        privateKeyPemBytes,
	}

	if args.CodeSigning {
		profile, profileErr := GetProfile(args.Target)
		if profileErr != nil {
			return nil, profileErr
		}
		if profile.OutputPFX {
			parsedCert, parseErr := x509.ParseCertificate(cert)
			if parseErr != nil {
				return nil, fmt.Errorf("cannot parse generated certificate for PKCS#12: %w", parseErr)
			}
			pfxBytes, pfxErr := toPFX(parsedCert, privateKey, args.PFXPassword, profile.LegacyPFX)
			if pfxErr != nil {
				return nil, fmt.Errorf("cannot generate PKCS#12: %w", pfxErr)
			}
			kp.PFX = pfxBytes
		}
	}

	return kp, nil
}

// newCertificateTemplate builds the certificate template described by args for
// a certificate that certifies pub.
func newCertificateTemplate(args *Args, pub crypto.PublicKey) (*x509.Certificate, error) {
	startTimestamp := time.Now()
	expirationTimestamp := startTimestamp.Add(args.Validity)
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)

	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("cannot create serial number for X.509 certificate, %w", err)
	}

	pkixName := argsToPkixName(args, serialNumber.String())

	var keyUsage x509.KeyUsage
	var extKeyUsage []x509.ExtKeyUsage
	if args.CodeSigning {
		keyUsage = x509.KeyUsageDigitalSignature
		extKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}
	} else {
		keyUsage = x509.KeyUsageDigitalSignature
		if _, isRSA := pub.(*rsa.PublicKey); isRSA {
			keyUsage |= x509.KeyUsageKeyEncipherment
		}
		extKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	}

	certTemplate := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkixName,
		Issuer:                pkixName,
		NotBefore:             startTimestamp,
		NotAfter:              expirationTimestamp,
		KeyUsage:              keyUsage,
		ExtKeyUsage:           extKeyUsage,
		BasicConstraintsValid: true,
		IsCA:                  args.CA,
	}

	if args.CA {
		certTemplate.KeyUsage |= x509.KeyUsageCertSign
	}

	if !args.CodeSigning {
		// Clone so the caller's Hostnames are never appended to in place.
		hostnames := append(slices.Clone(args.Hostnames), "localhost", "127.0.0.1")
		certTemplate.DNSNames, certTemplate.IPAddresses, err = subjectAltNames(hostnames)
		if err != nil {
			return nil, err
		}
	}

	return certTemplate, nil
}

// checkIssuer returns an error unless issuer can sign a certificate made from
// template at time now in a way that clients will accept: it must be a CA that
// is allowed to sign certificates, valid now, allow another CA below it when
// template is one, and allow the extended key usages template asks for.
func checkIssuer(issuer *x509.Certificate, template *x509.Certificate, now time.Time) error {
	cn := issuer.Subject.CommonName
	switch {
	case !issuer.BasicConstraintsValid || !issuer.IsCA:
		return fmt.Errorf("parent certificate %q is not a CA certificate, so it cannot sign other certificates; create the parent with --ca", cn)
	case issuer.KeyUsage != 0 && issuer.KeyUsage&x509.KeyUsageCertSign == 0:
		return fmt.Errorf("parent certificate %q does not allow certificate signing (key usage cert sign)", cn)
	case now.After(issuer.NotAfter):
		return fmt.Errorf("parent certificate %q expired at %s", cn, issuer.NotAfter.Format(time.RFC3339))
	case now.Before(issuer.NotBefore):
		return fmt.Errorf("parent certificate %q is not valid until %s", cn, issuer.NotBefore.Format(time.RFC3339))
	case template.IsCA && issuer.MaxPathLenZero && issuer.MaxPathLen == 0:
		return fmt.Errorf("parent certificate %q has a path length of 0, so it can only sign leaf certificates, not another CA", cn)
	}

	if len(issuer.ExtKeyUsage) == 0 || slices.Contains(issuer.ExtKeyUsage, x509.ExtKeyUsageAny) {
		return nil
	}
	for _, usage := range template.ExtKeyUsage {
		if slices.Contains(issuer.ExtKeyUsage, usage) {
			continue
		}
		err := fmt.Errorf("parent certificate %q is limited to %s, so clients would reject a %s certificate it signs", cn, extKeyUsageNames(issuer.ExtKeyUsage), extKeyUsageName(usage))
		if usage == x509.ExtKeyUsageCodeSigning {
			// CAs made by --ca, --chain, and --spec are limited to TLS.
			err = fmt.Errorf("%w; sign code signing certificates with a CA that has no extended key usage limit, such as a YubiKey root, or leave them self-signed", err)
		}
		return err
	}
	return nil
}

func extKeyUsageNames(usages []x509.ExtKeyUsage) string {
	names := make([]string, 0, len(usages))
	for _, u := range usages {
		names = append(names, extKeyUsageName(u))
	}
	return strings.Join(names, " and ")
}

func extKeyUsageName(usage x509.ExtKeyUsage) string {
	switch usage {
	case x509.ExtKeyUsageServerAuth:
		return "TLS server"
	case x509.ExtKeyUsageClientAuth:
		return "TLS client"
	case x509.ExtKeyUsageCodeSigning:
		return "code signing"
	}
	return fmt.Sprintf("extended key usage %d", usage)
}

// signatureAlgorithm returns the algorithm used to sign certificates with the
// private key belonging to pub.
func signatureAlgorithm(pub crypto.PublicKey, codeSigning bool) (x509.SignatureAlgorithm, error) {
	switch pub.(type) {
	case *rsa.PublicKey:
		if codeSigning {
			return x509.SHA256WithRSA, nil
		}
		return x509.SHA512WithRSA, nil
	case *ecdsa.PublicKey:
		if codeSigning {
			return x509.ECDSAWithSHA256, nil
		}
		return x509.ECDSAWithSHA512, nil
	}
	return x509.UnknownSignatureAlgorithm, fmt.Errorf("signing key type %T is not supported", pub)
}

// CreateSelfSignedCertificate creates a self-signed certificate for a private
// key held outside of certtool, such as on a hardware security token. Only the
// public certificate is produced because the private key never leaves signer.
//
// When args.CA is set the certificate is a root CA that is not restricted to
// particular extended key usages or names, so it can issue certificates for any
// purpose, including code signing.
func CreateSelfSignedCertificate(args *Args, signer crypto.Signer) (*x509.Certificate, error) {
	fillDefaults(args)

	certTemplate, err := newCertificateTemplate(args, signer.Public())
	if err != nil {
		return nil, err
	}

	if args.CA {
		// Clients check extended key usages along the whole chain, so a root
		// limited to TLS could not issue code signing certificates.
		certTemplate.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature
		certTemplate.ExtKeyUsage = nil
		certTemplate.DNSNames = nil
		certTemplate.IPAddresses = nil
	}

	certTemplate.SignatureAlgorithm, err = signatureAlgorithm(signer.Public(), args.CodeSigning)
	if err != nil {
		return nil, err
	}

	der, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, signer.Public(), signer)
	if err != nil {
		return nil, fmt.Errorf("cannot create X.509 public certificate, %w", err)
	}

	return x509.ParseCertificate(der)
}

// EncodeCertificatePEM returns the PEM encoding of cert.
func EncodeCertificatePEM(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
}

func argsToPkixName(args *Args, serialNumber string) pkix.Name {
	return pkix.Name{
		Country:            []string{args.Country},
		Organization:       []string{args.Organization},
		OrganizationalUnit: []string{args.OrganizationalUnit},
		Locality:           []string{args.Locality},
		Province:           []string{args.Province},
		CommonName:         args.CommonName,
		SerialNumber:       serialNumber,
	}
}

func generatePrivateKeyFromType(keyType KeyType) (any, error) {
	switch strings.ToUpper(keyType.Algorithm) {
	case rsaAlgorithm:
		if keyType.KeyLength < 2048 {
			return nil, fmt.Errorf("'%s-%d' key type has a key length below 2048", keyType.Algorithm, keyType.KeyLength)
		}
		return rsa.GenerateKey(rand.Reader, keyType.KeyLength)
	case ecdsaAlgorithm:
		switch keyType.KeyLength {
		case 224:
			return ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
		case 256:
			return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		case 384:
			return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		case 521:
			fallthrough
		case 0:
			return ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		}
	}
	return nil, fmt.Errorf("key type '%v' is not valid", keyType)
}

// ReadKeyPair takes PEM-encoded public certificate/private key pairs and returns the Go classes for them so they can be used for encryption or signing.
func ReadKeyPair(publicCertFileData []byte, privateKeyFileData []byte) (*x509.Certificate, any, error) {
	// Verify that we can load the public/private key pair.
	publicCertPemBlock, remainder := pem.Decode(publicCertFileData)
	if publicCertPemBlock == nil {
		return nil, nil, fmt.Errorf("public certificate contains no PEM data")
	}
	if len(remainder) > 0 {
		return nil, nil, fmt.Errorf("public certificate has a PEM remainder of %d bytes", len(remainder))
	}

	publicCertificate, err := x509.ParseCertificate(publicCertPemBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot parse X.509 certificate, %w", err)
	}

	privateKeyPemBlock, remainder := pem.Decode(privateKeyFileData)
	if privateKeyPemBlock == nil {
		return nil, nil, fmt.Errorf("private key contains no PEM data")
	}
	if len(remainder) > 0 {
		return nil, nil, fmt.Errorf("private key has a PEM remainder of %d bytes", len(remainder))
	}

	switch privateKeyPemBlock.Type {
	case rsaPrivateKeyPEMType:
		privateKey, err := x509.ParsePKCS1PrivateKey(privateKeyPemBlock.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("cannot parse PKCS1 encoding for private key, %w", err)
		}

		return publicCertificate, privateKey, nil
	case ecPrivateKeyPEMType:
		privateKey, err := x509.ParseECPrivateKey(privateKeyPemBlock.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("cannot parse elliptical curve private key, %w", err)
		}

		return publicCertificate, privateKey, nil
	}

	return nil, nil, fmt.Errorf("cannot parse private key PEM type, %s, is not supported", privateKeyPemBlock.Type)
}

func publicKey(priv any) (any, error) {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey, nil
	case *ecdsa.PrivateKey:
		return &k.PublicKey, nil
	default:
		return nil, fmt.Errorf("unsupported private key type %T", priv)
	}
}

func pemBlockForKey(privateKey any) (*pem.Block, error) {
	switch k := privateKey.(type) {
	case *rsa.PrivateKey:
		return &pem.Block{Type: rsaPrivateKeyPEMType, Bytes: x509.MarshalPKCS1PrivateKey(k)}, nil
	case *ecdsa.PrivateKey:
		b, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			return nil, err
		}

		return &pem.Block{Type: ecPrivateKeyPEMType, Bytes: b}, nil
	default:
		return nil, fmt.Errorf("private Key %v is not a valid private key", privateKey)
	}
}

// ParseName parses the RFC-2253 encoded Distinguished Names.
func ParseName(subject string) (pkix.Name, error) {
	name := pkix.Name{}
	subject = strings.ReplaceAll(subject, "\\"+subjectDelimiter, subjectDelimiterReplacement)
	parts := strings.Split(subject, subjectDelimiter)

	for _, part := range parts {
		vals := strings.Split(part, partDelimiter)
		if len(vals) < numDistinguishedNameSegmentParts {
			continue
		} else if len(vals) > numDistinguishedNameSegmentParts {
			return pkix.Name{}, fmt.Errorf("AttributeType '%s' has too many parts, %v", vals[0], vals)
		}

		value := strings.ReplaceAll(vals[1], subjectDelimiterReplacement, subjectDelimiter)

		switch strings.ToUpper(vals[0]) {
		case "CN":
			name.CommonName = value
		case "OU":
			name.OrganizationalUnit = append(name.OrganizationalUnit, value)
		case "O":
			name.Organization = append(name.Organization, value)
		case "L":
			name.Locality = append(name.Locality, value)
		case "ST":
			name.Province = append(name.Province, value)
		case "C":
			name.Country = append(name.Country, value)
		case "STREET":
			name.StreetAddress = append(name.StreetAddress, value)
		case "POSTALCODE":
			name.PostalCode = append(name.PostalCode, value)
		default:
			return pkix.Name{}, fmt.Errorf("'%s' is not a valid RFC-2253 AttributeType", vals[0])
		}
	}

	return name, nil
}

// ReadKeyPairFromFile is a convenience method for loading the key pair from a file.
func ReadKeyPairFromFile(publicCertificateFile string, privateKeyFile string) (*KeyPair, error) {
	if publicCertificateFile == "" && privateKeyFile == "" {
		return nil, fmt.Errorf("public certificate and private key were not provided")
	}
	if publicCertificateFile != "" && privateKeyFile == "" {
		return nil, fmt.Errorf("public certificate was provided without a private key")
	}
	if publicCertificateFile == "" && privateKeyFile != "" {
		return nil, fmt.Errorf("private key was provided without a public certificate")
	}

	pub, err := os.ReadFile(filepath.Clean(publicCertificateFile))
	if err != nil {
		return nil, fmt.Errorf("cannot read the public certificate file (%s), %w", publicCertificateFile, err)
	}
	priv, err := os.ReadFile(filepath.Clean(privateKeyFile))
	if err != nil {
		return nil, fmt.Errorf("cannot read the private key file (%s), %w", privateKeyFile, err)
	}

	return &KeyPair{
		PublicCertificate: pub,
		PrivateKey:        priv,
	}, nil
}

// GenerateAndWriteKeyPair generates a new key pair and writes it to the specified files.
func GenerateAndWriteKeyPair(args *Args, publicCertificateFile string, privateKeyFile string) (*KeyPair, error) {
	if len(publicCertificateFile) == 0 {
		return nil, fmt.Errorf("public certificate file path must not be empty")
	}
	if len(privateKeyFile) == 0 {
		return nil, fmt.Errorf("private key file path must not be empty")
	}
	kp, err := GenerateKeyPair(args)
	if err != nil {
		return nil, err
	}
	if err := WriteKeyPair(kp, publicCertificateFile, privateKeyFile); err != nil {
		return nil, err
	}
	return kp, nil
}

// WriteKeyPair writes the public certificate and private key to the specified files with mode 0644 and 0600 respectively.
func WriteKeyPair(kp *KeyPair, publicCertificateFile string, privateKeyFile string) error {
	if err := writeFile(publicCertificateFile, kp.PublicCertificate, 0o644); err != nil {
		return err
	}
	if err := writeFile(privateKeyFile, kp.PrivateKey, 0o600); err != nil {
		return err
	}
	return nil
}

// WriteCertificate writes the PEM encoding of cert to publicCertificateFile with mode 0644.
func WriteCertificate(cert *x509.Certificate, publicCertificateFile string) error {
	return writeFile(publicCertificateFile, EncodeCertificatePEM(cert), 0o644)
}

// WritePFX writes the PKCS#12 bundle from kp to pfxFile with mode 0600.
func WritePFX(kp *KeyPair, pfxFile string) error {
	if len(kp.PFX) == 0 {
		return fmt.Errorf("KeyPair does not contain PKCS#12 data")
	}
	return writeFile(pfxFile, kp.PFX, 0o600)
}

func writeFile(fileName string, data []byte, mode os.FileMode) error {
	return os.WriteFile(fileName, data, mode)
}
