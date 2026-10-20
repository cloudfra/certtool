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

package yubikey

import (
	"testing"
)

func TestParseTouchPolicy(t *testing.T) {
	testCases := []struct {
		in      string
		want    TouchPolicy
		wantErr bool
	}{
		{in: "never", want: TouchNever},
		{in: "Always", want: TouchAlways},
		{in: " cached ", want: TouchCached},
		{in: "", wantErr: true},
		{in: "sometimes", wantErr: true},
	}
	for _, tc := range testCases {
		t.Run(tc.in, func(t *testing.T) {
			got, err := ParseTouchPolicy(tc.in)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ParseTouchPolicy(%q) err = %v, wantErr %v", tc.in, err, tc.wantErr)
			}
			if got != tc.want {
				t.Errorf("ParseTouchPolicy(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestParseSlotKey(t *testing.T) {
	testCases := []struct {
		in      string
		want    uint32
		wantErr bool
	}{
		{in: "", want: 0x9c},
		{in: "9a", want: 0x9a},
		{in: "0x82", want: 0x82},
		{in: "9C", want: 0x9c},
		{in: "zz", wantErr: true},
		{in: "100", wantErr: true},
	}
	for _, tc := range testCases {
		t.Run(tc.in, func(t *testing.T) {
			got, err := parseSlotKey(tc.in)
			if (err != nil) != tc.wantErr {
				t.Fatalf("parseSlotKey(%q) err = %v, wantErr %v", tc.in, err, tc.wantErr)
			}
			if got != tc.want {
				t.Errorf("parseSlotKey(%q) = %#x, want %#x", tc.in, got, tc.want)
			}
		})
	}
}
