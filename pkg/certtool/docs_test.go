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
	"bytes"
	"io/fs"
	"os"
	"regexp"
	"slices"
	"testing"
)

var yamlFence = regexp.MustCompile("(?s)```yaml\\n(.*?)```")

// TestSpecDocExamplesAreValid keeps every YAML example in docs/spec.md and the
// agent skill's spec reference parseable and valid, so the documentation
// cannot drift from the spec format.
func TestSpecDocExamplesAreValid(t *testing.T) {
	for _, path := range []string{
		"docs/spec.md",
		"skills/certtool/references/spec-format.md",
	} {
		t.Run(path, func(t *testing.T) {
			doc, err := fs.ReadFile(os.DirFS("../.."), path)
			if err != nil {
				t.Fatalf("ReadFile() err = %v", err)
			}

			blocks := yamlExamples(doc)
			if len(blocks) == 0 {
				t.Fatalf("no yaml examples found in %s", path)
			}
			for i, block := range blocks {
				if _, err := UnmarshalSpec(block); err != nil {
					t.Errorf("yaml example #%d in %s is invalid: %v\n%s", i+1, path, err, block)
				}
			}
		})
	}
}

// TestSpecDocScenarioExample keeps the --scenario web example in docs/spec.md
// identical to what the scenario writes.
func TestSpecDocScenarioExample(t *testing.T) {
	t.Parallel()
	doc, err := fs.ReadFile(os.DirFS("../.."), "docs/spec.md")
	if err != nil {
		t.Fatalf("ReadFile() err = %v", err)
	}
	golden, err := os.ReadFile("testdata/scenarios/web.yaml")
	if err != nil {
		t.Fatalf("ReadFile() err = %v", err)
	}
	want := normalizeNewlines(golden)
	if !slices.ContainsFunc(yamlExamples(doc), func(b []byte) bool { return bytes.Equal(b, want) }) {
		t.Errorf("docs/spec.md has no yaml example equal to testdata/scenarios/web.yaml; copy it into the \"Starting from a scenario\" section")
	}
}

// TestYAMLExamplesCRLF guards against Windows checkouts, where the markdown
// files have CRLF line endings.
func TestYAMLExamplesCRLF(t *testing.T) {
	doc := []byte("text\r\n\r\n```yaml\r\n- commonName: a\r\n```\r\n")
	blocks := yamlExamples(doc)
	if len(blocks) != 1 {
		t.Fatalf("yamlExamples() found %d blocks, want 1", len(blocks))
	}
	if _, err := UnmarshalSpec(blocks[0]); err != nil {
		t.Errorf("UnmarshalSpec() err = %v", err)
	}
}

// yamlExamples returns the contents of every fenced yaml block in a markdown
// document, regardless of its line-ending style.
func yamlExamples(doc []byte) [][]byte {
	doc = normalizeNewlines(doc)
	matches := yamlFence.FindAllSubmatch(doc, -1)
	blocks := make([][]byte, 0, len(matches))
	for _, m := range matches {
		blocks = append(blocks, m[1])
	}
	return blocks
}

func normalizeNewlines(b []byte) []byte {
	return bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n"))
}
