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
	"strings"
	"testing"
)

func TestGetProfile(t *testing.T) {
	testCases := []struct {
		input      string
		wantAlgo   string
		wantLen    int
		wantPFX    bool
		wantLegacy bool
	}{
		{input: "windows7",  wantAlgo: "RSA",   wantLen: 2048, wantPFX: true,  wantLegacy: true},
		{input: "win7",      wantAlgo: "RSA",   wantLen: 2048, wantPFX: true,  wantLegacy: true},
		{input: "windows8",  wantAlgo: "RSA",   wantLen: 2048, wantPFX: true,  wantLegacy: true},
		{input: "win8",      wantAlgo: "RSA",   wantLen: 2048, wantPFX: true,  wantLegacy: true},
		{input: "windows10", wantAlgo: "ECDSA", wantLen: 256,  wantPFX: true,  wantLegacy: false},
		{input: "win10",     wantAlgo: "ECDSA", wantLen: 256,  wantPFX: true,  wantLegacy: false},
		{input: "windows11", wantAlgo: "ECDSA", wantLen: 256,  wantPFX: true,  wantLegacy: false},
		{input: "win11",     wantAlgo: "ECDSA", wantLen: 256,  wantPFX: true,  wantLegacy: false},
		{input: "linux",     wantAlgo: "ECDSA", wantLen: 256,  wantPFX: false, wantLegacy: false},
		{input: "WINDOWS10", wantAlgo: "ECDSA", wantLen: 256,  wantPFX: true,  wantLegacy: false},
	}
	for _, tc := range testCases {
		tc := tc
		t.Run(tc.input, func(t *testing.T) {
			t.Parallel()
			p, err := GetProfile(tc.input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if p.KeyType.Algorithm != tc.wantAlgo {
				t.Errorf("Algorithm: got %s, want %s", p.KeyType.Algorithm, tc.wantAlgo)
			}
			if p.KeyType.KeyLength != tc.wantLen {
				t.Errorf("KeyLength: got %d, want %d", p.KeyType.KeyLength, tc.wantLen)
			}
			if p.OutputPFX != tc.wantPFX {
				t.Errorf("OutputPFX: got %v, want %v", p.OutputPFX, tc.wantPFX)
			}
			if p.LegacyPFX != tc.wantLegacy {
				t.Errorf("LegacyPFX: got %v, want %v", p.LegacyPFX, tc.wantLegacy)
			}
		})
	}
}

func TestGetProfile_Unknown(t *testing.T) {
	_, err := GetProfile("windowsXP")
	if err == nil {
		t.Error("expected error for unknown target, got nil")
	}
	if !strings.Contains(err.Error(), "windows7") {
		t.Errorf("error message should list valid targets, got: %s", err.Error())
	}
}
