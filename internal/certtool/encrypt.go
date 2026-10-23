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
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"
	"github.com/cloudfra/certtool/internal/logging"
	certlib "github.com/cloudfra/certtool/pkg/certtool"
	"github.com/cloudfra/certtool/pkg/yubikey"
)

// AgeIdentityEnv holds age identities (AGE-SECRET-KEY-1...), one per line,
// that decrypt encrypted private keys.
const AgeIdentityEnv = "CERTTOOL_AGE_IDENTITY"

// validateEncryption rejects encryption options that would be ignored.
func validateEncryption(args Args) error {
	decrypts := args.AgeIdentityFile != "" || args.AgeYubiKey
	switch {
	case args.YubiKeyGenerateRoot && (args.EncryptTo != "" || decrypts):
		return errors.New("--encrypt-to, --age-identity-file, and --age-yubikey do not apply to --yubikey-generate-root, whose key never leaves the YubiKey")
	case args.ExportSpec != "" && (args.EncryptTo != "" || decrypts):
		return errors.New("--encrypt-to, --age-identity-file, and --age-yubikey do not apply to --export-spec, which writes no keys")
	case decrypts && args.ParentPrivateKey == "" && args.Spec == "" && args.Chain == "":
		return errors.New("--age-identity-file and --age-yubikey decrypt --parent-private-key, or the keys that --spec and --chain reuse; without those there is nothing to decrypt")
	}
	return nil
}

// keyEncryption builds the encryption of the private keys from the options.
// token is the open YubiKey, needed with --age-yubikey.
func keyEncryption(args Args, token *yubikey.Token) (*certlib.KeyEncryption, error) {
	enc := &certlib.KeyEncryption{}
	for _, s := range splitStrings(args.EncryptTo) {
		r, err := certlib.ParseAgeRecipient(s)
		if err != nil {
			return nil, fmt.Errorf("--encrypt-to: %w", err)
		}
		enc.Recipients = append(enc.Recipients, r)
	}

	if env := os.Getenv(AgeIdentityEnv); env != "" {
		ids, err := age.ParseIdentities(strings.NewReader(env))
		if err != nil {
			// The error never includes the identity itself.
			return nil, fmt.Errorf("the %s environment variable must hold age identities (AGE-SECRET-KEY-1...), one per line: %w", AgeIdentityEnv, err)
		}
		enc.Identities = append(enc.Identities, ids...)
	}
	for _, path := range splitStrings(args.AgeIdentityFile) {
		ids, err := readIdentityFile(path)
		if err != nil {
			return nil, err
		}
		enc.Identities = append(enc.Identities, ids...)
	}
	if args.AgeYubiKey {
		ids, err := token.AgeIdentities()
		if err != nil {
			return nil, fmt.Errorf("--age-yubikey: %w", err)
		}
		enc.Identities = append(enc.Identities, ids...)
	}
	return enc, nil
}

func readIdentityFile(path string) ([]age.Identity, error) {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("--age-identity-file: %w", err)
	}
	defer f.Close() //nolint:errcheck // Read only.
	ids, err := age.ParseIdentities(f)
	if err != nil {
		return nil, fmt.Errorf("--age-identity-file %s must hold age identities (AGE-SECRET-KEY-1...); for a key on a YubiKey use --age-yubikey instead of the plugin's identity file: %w", path, err)
	}
	return ids, nil
}

// logEncrypted reports where an encrypted key was written.
func logEncrypted(ctx context.Context, enc *certlib.KeyEncryption, path string) {
	if enc.Encrypts() {
		logging.FromContext(ctx).Info("private key encrypted with age", "path", path, "recipients", len(enc.Recipients))
	}
}
