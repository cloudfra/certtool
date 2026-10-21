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
	"errors"
	"runtime"
	"strings"
	"testing"
)

func TestStubIsUnsupported(t *testing.T) {
	if Supported() {
		t.Error("Supported() = true, want false")
	}

	token, err := Open(Config{})
	if token != nil {
		t.Errorf("Open() = %v, want nil", token)
	}
	if !errors.Is(err, errors.ErrUnsupported) {
		t.Errorf("Open() err = %v, want it to wrap errors.ErrUnsupported", err)
	}
	platform := runtime.GOOS + "/" + runtime.GOARCH
	if err == nil || !strings.Contains(err.Error(), platform) || !strings.Contains(err.Error(), "CGO_ENABLED=1") {
		t.Errorf("Open() err = %v, want it to name %s and how to get YubiKey support", err, platform)
	}

	var stub *Token
	if _, err := stub.Issuer(); !errors.Is(err, errors.ErrUnsupported) {
		t.Errorf("Issuer() err = %v, want errors.ErrUnsupported", err)
	}
	if _, err := stub.GenerateRoot(nil, TouchNever, false); !errors.Is(err, errors.ErrUnsupported) {
		t.Errorf("GenerateRoot() err = %v, want errors.ErrUnsupported", err)
	}
	if err := stub.Close(); err != nil {
		t.Errorf("Close() err = %v, want nil", err)
	}
}
