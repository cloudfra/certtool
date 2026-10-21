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

//go:build windows || (cgo && ((linux && !android) || (darwin && !ios) || freebsd || openbsd))

package yubikey

import (
	"testing"

	"github.com/cloudfra/certtool/pkg/certtool"
	"github.com/go-piv/piv-go/v2/piv"
)

func TestPIVSlot(t *testing.T) {
	retired, _ := piv.RetiredKeyManagementSlot(0x95)
	testCases := []struct {
		in      string
		want    piv.Slot
		wantErr bool
	}{
		{in: "", want: piv.SlotSignature},
		{in: "9a", want: piv.SlotAuthentication},
		{in: "9c", want: piv.SlotSignature},
		{in: "9d", want: piv.SlotKeyManagement},
		{in: "9e", want: piv.SlotCardAuthentication},
		{in: "95", want: retired},
		{in: "f9", wantErr: true},
		{in: "81", wantErr: true},
	}
	for _, tc := range testCases {
		t.Run(tc.in, func(t *testing.T) {
			got, err := pivSlot(tc.in)
			if (err != nil) != tc.wantErr {
				t.Fatalf("pivSlot(%q) err = %v, wantErr %v", tc.in, err, tc.wantErr)
			}
			if got != tc.want {
				t.Errorf("pivSlot(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestPIVAlgorithm(t *testing.T) {
	testCases := []struct {
		keyType certtool.KeyType
		want    piv.Algorithm
		wantErr bool
	}{
		{keyType: certtool.KeyType{Algorithm: "ECDSA", KeyLength: 256}, want: piv.AlgorithmEC256},
		{keyType: certtool.KeyType{Algorithm: "ecdsa", KeyLength: 384}, want: piv.AlgorithmEC384},
		{keyType: certtool.KeyType{Algorithm: "RSA", KeyLength: 2048}, want: piv.AlgorithmRSA2048},
		{keyType: certtool.KeyType{Algorithm: "RSA", KeyLength: 4096}, want: piv.AlgorithmRSA4096},
		{keyType: certtool.KeyType{Algorithm: "ECDSA", KeyLength: 521}, wantErr: true},
		{keyType: certtool.KeyType{Algorithm: "RSA", KeyLength: 1024}, wantErr: true},
	}
	for _, tc := range testCases {
		t.Run(tc.keyType.Algorithm, func(t *testing.T) {
			got, err := pivAlgorithm(&tc.keyType)
			if (err != nil) != tc.wantErr {
				t.Fatalf("pivAlgorithm(%v) err = %v, wantErr %v", tc.keyType, err, tc.wantErr)
			}
			if got != tc.want {
				t.Errorf("pivAlgorithm(%v) = %v, want %v", tc.keyType, got, tc.want)
			}
		})
	}
}
