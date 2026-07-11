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

const (
	windows7Target  = "windows7"
	windows10Target = "windows10"
	windows11Target = "windows11"
	linuxTarget     = "linux"
)

// TargetProfile holds cert generation defaults for a named platform target.
type TargetProfile struct {
	KeyType   KeyType
	OutputPFX bool
	LegacyPFX bool
}

var targetProfiles = map[string]TargetProfile{
	windows7Target: {
		KeyType:   KeyType{Algorithm: rsaAlgorithm, KeyLength: 2048},
		OutputPFX: true,
		LegacyPFX: true,
	},
	windows10Target: {
		KeyType:   KeyType{Algorithm: ecdsaAlgorithm, KeyLength: 256},
		OutputPFX: true,
		LegacyPFX: false,
	},
	windows11Target: {
		KeyType:   KeyType{Algorithm: ecdsaAlgorithm, KeyLength: 256},
		OutputPFX: true,
		LegacyPFX: false,
	},
	linuxTarget: {
		KeyType:   KeyType{Algorithm: ecdsaAlgorithm, KeyLength: 256},
		OutputPFX: false,
		LegacyPFX: false,
	},
}

var profileAliases = map[string]string{
	"win7":       windows7Target,
	"windows8":   windows7Target,
	"win8":       windows7Target,
	"windows8.1": windows7Target,
	"win8.1":     windows7Target,
	"win10":      windows10Target,
	"win11":      windows11Target,
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
