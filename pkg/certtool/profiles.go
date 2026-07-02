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
	"fmt"
	"strings"
)

// TargetProfile holds cert generation defaults for a named platform target.
type TargetProfile struct {
	KeyType   KeyType
	OutputPFX bool
	LegacyPFX bool
}

var targetProfiles = map[string]TargetProfile{
	"windows7": {
		KeyType:   KeyType{Algorithm: "RSA", KeyLength: 2048},
		OutputPFX: true,
		LegacyPFX: true,
	},
	"windows10": {
		KeyType:   KeyType{Algorithm: "ECDSA", KeyLength: 256},
		OutputPFX: true,
		LegacyPFX: false,
	},
	"windows11": {
		KeyType:   KeyType{Algorithm: "ECDSA", KeyLength: 256},
		OutputPFX: true,
		LegacyPFX: false,
	},
	"linux": {
		KeyType:   KeyType{Algorithm: "ECDSA", KeyLength: 256},
		OutputPFX: false,
		LegacyPFX: false,
	},
}

var profileAliases = map[string]string{
	"win7":       "windows7",
	"windows8":   "windows7",
	"win8":       "windows7",
	"windows8.1": "windows7",
	"win8.1":     "windows7",
	"win10":      "windows10",
	"win11":      "windows11",
}

// GetProfile returns the TargetProfile for the given target name or alias.
func GetProfile(target string) (TargetProfile, error) {
	normalized := strings.ToLower(strings.TrimSpace(target))
	if alias, ok := profileAliases[normalized]; ok {
		normalized = alias
	}
	if profile, ok := targetProfiles[normalized]; ok {
		return profile, nil
	}
	return TargetProfile{}, fmt.Errorf("unknown target %q: valid targets are windows7 (aliases: win7, windows8, win8), windows10 (alias: win10), windows11 (alias: win11), linux", target)
}
