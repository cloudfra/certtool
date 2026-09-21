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
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

var yamlFence = regexp.MustCompile("(?s)```yaml\\n(.*?)```")

// TestSpecDocExamplesAreValid keeps every YAML example in docs/spec.md
// parseable and valid, so the documentation cannot drift from the spec format.
func TestSpecDocExamplesAreValid(t *testing.T) {
	doc, err := os.ReadFile(filepath.Join("..", "..", "docs", "spec.md"))
	if err != nil {
		t.Fatalf("ReadFile() err = %v", err)
	}

	blocks := yamlExamples(doc)
	if len(blocks) == 0 {
		t.Fatal("no yaml examples found in docs/spec.md")
	}
	for i, block := range blocks {
		if _, err := UnmarshalSpec(block); err != nil {
			t.Errorf("yaml example #%d in docs/spec.md is invalid: %v\n%s", i+1, err, block)
		}
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
	doc = bytes.ReplaceAll(doc, []byte("\r\n"), []byte("\n"))
	var blocks [][]byte
	for _, m := range yamlFence.FindAllSubmatch(doc, -1) {
		blocks = append(blocks, m[1])
	}
	return blocks
}
