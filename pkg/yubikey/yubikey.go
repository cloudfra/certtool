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

// Package yubikey uses the PIV applet of a YubiKey as a certificate authority.
// The CA private key is generated on, and never leaves, the YubiKey.
//
// YubiKey support needs PC/SC. On Windows it uses the system Winscard.dll and
// is always available, with or without cgo. On Linux, macOS, FreeBSD, and
// OpenBSD the binary must be built with cgo enabled (CGO_ENABLED=1); Linux and
// the BSDs also need the pcsclite development headers (libpcsclite-dev) to
// build. Android, iOS, and every other platform are not supported. On those,
// and on builds without cgo, Open returns an error wrapping
// errors.ErrUnsupported.
package yubikey

import (
	"fmt"
	"strconv"
	"strings"
)

// DefaultSlot is the PIV slot used when Config.Slot is empty. Slot 9c is the
// PIV digital signature slot, the conventional home of a signing key.
const DefaultSlot = "9c"

// Config selects a YubiKey and the PIV slot holding the CA key.
type Config struct {
	// Serial selects the YubiKey with this serial number. Zero selects the
	// only YubiKey connected and fails if more than one is connected.
	Serial uint32
	// Slot is the PIV slot holding the CA key and certificate, in hex: 9a, 9c,
	// 9d, 9e, or a retired key management slot 82 through 95. Defaults to 9c.
	Slot string
	// PIN unlocks the CA key. When empty, PINPrompt is called if a PIN is needed.
	PIN string
	// PINPrompt interactively requests the PIN. It is called at most once.
	PINPrompt func() (string, error)
	// ManagementKey authorizes writing keys and certificates to the YubiKey, in
	// hex. When empty, the PIN-protected management key stored on the YubiKey
	// is used if there is one, otherwise the factory default management key.
	ManagementKey string
	// BeforeSign is called before each signature made with the CA key, for
	// example to remind the user to touch the YubiKey. It may be nil.
	BeforeSign func()
}

// TouchPolicy is whether the YubiKey must be touched to use the CA key.
type TouchPolicy string

const (
	// TouchNever never requires a touch.
	TouchNever TouchPolicy = "never"
	// TouchAlways requires a touch for every signature.
	TouchAlways TouchPolicy = "always"
	// TouchCached requires a touch, then allows further signatures without
	// one for 15 seconds.
	TouchCached TouchPolicy = "cached"
)

// ParseTouchPolicy parses never, always, or cached.
func ParseTouchPolicy(s string) (TouchPolicy, error) {
	switch p := TouchPolicy(strings.ToLower(strings.TrimSpace(s))); p {
	case TouchNever, TouchAlways, TouchCached:
		return p, nil
	}
	return "", fmt.Errorf("YubiKey touch policy %q is not valid, must be never, always, or cached", s)
}

// parseSlotKey parses a PIV slot key reference such as "9c" or "0x82".
func parseSlotKey(s string) (uint32, error) {
	if s == "" {
		s = DefaultSlot
	}
	key, err := strconv.ParseUint(strings.TrimPrefix(strings.ToLower(strings.TrimSpace(s)), "0x"), 16, 8)
	if err != nil {
		return 0, fmt.Errorf("YubiKey slot %q is not a hex slot number", s)
	}
	return uint32(key), nil
}
