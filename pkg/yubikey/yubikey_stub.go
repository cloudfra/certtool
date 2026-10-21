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

//go:build !windows && (!cgo || android || ios || !(linux || darwin || freebsd || openbsd))

package yubikey

import (
	"crypto/x509"
	"errors"
	"fmt"
	"runtime"

	"github.com/cloudfra/certtool/pkg/certtool"
)

var errUnsupported = fmt.Errorf("this build of certtool (%s/%s) does not support YubiKeys; they are supported on Windows, and on Linux, macOS, FreeBSD, and OpenBSD when built with CGO_ENABLED=1: %w", runtime.GOOS, runtime.GOARCH, errors.ErrUnsupported)

// Supported reports whether this build can use YubiKeys.
func Supported() bool { return false }

// Token is an open YubiKey.
type Token struct{}

// Open always fails because this build does not support YubiKeys.
func Open(Config) (*Token, error) { return nil, errUnsupported }

// Serial returns the serial number of the YubiKey.
func (*Token) Serial() uint32 { return 0 }

// Issuer always fails because this build does not support YubiKeys.
func (*Token) Issuer() (*certtool.Issuer, error) { return nil, errUnsupported }

// GenerateRoot always fails because this build does not support YubiKeys.
func (*Token) GenerateRoot(*certtool.Args, TouchPolicy, bool) (*x509.Certificate, error) {
	return nil, errUnsupported
}

// FactoryDefaults returns nothing, because this build cannot use YubiKeys.
func (*Token) FactoryDefaults() []string { return nil }

// Close does nothing.
func (*Token) Close() error { return nil }
