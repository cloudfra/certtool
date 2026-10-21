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

package main

import (
	"flag"
	"io/fs"
	"os"
	"regexp"
	"strings"
	"testing"
)

var flagMention = regexp.MustCompile(`(?:^|[^-\w])--([a-z][a-z0-9-]*)`)

// TestSkillFlags keeps the agent skill in step with the flags: every flag the
// skill names must exist, and the flag reference must list every flag.
func TestSkillFlags(t *testing.T) {
	flags := newFlagSet()
	if _, err := parseFlags(flags, nil); err != nil {
		t.Fatal(err)
	}

	for _, path := range []string{
		"skills/certtool/SKILL.md",
		"skills/certtool/references/flags.md",
		"skills/certtool/references/spec-format.md",
		"llms.txt",
	} {
		doc := readRepoFile(t, path)
		for _, m := range flagMention.FindAllStringSubmatch(doc, -1) {
			if name := m[1]; name != "help" && flags.Lookup(name) == nil {
				t.Errorf("%s names --%s, which is not a certtool flag", path, name)
			}
		}
	}

	reference := readRepoFile(t, "skills/certtool/references/flags.md")
	flags.VisitAll(func(f *flag.Flag) {
		if !strings.Contains(reference, "`--"+f.Name+"`") {
			t.Errorf("references/flags.md does not document --%s", f.Name)
		}
	})
}

// readRepoFile reads a file by its slash-separated path from the repository root.
func readRepoFile(t *testing.T, path string) string {
	t.Helper()

	doc, err := fs.ReadFile(os.DirFS("../.."), path)
	if err != nil {
		t.Fatalf("ReadFile() err = %v", err)
	}
	return string(doc)
}
