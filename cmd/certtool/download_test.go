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
	"path"
	"regexp"
	"testing"
)

var (
	// The release workflow lists its files as globs, such as
	// build/release/*-linux_amd64, that match every app it builds.
	releaseAsset  = regexp.MustCompile(`build/release/(\*-[A-Za-z0-9_.-]+)`)
	downloadAsset = regexp.MustCompile(`releases/(?:latest/download|download/[^/\s]+)/([A-Za-z0-9_.-]+)`)
	namedAsset    = regexp.MustCompile("`(certtool-[A-Za-z0-9_]+(?:\\.exe)?)`")
)

// TestDownloadLinks keeps the documented download links pointing at files the
// release workflow publishes, so they never return 404.
func TestDownloadLinks(t *testing.T) {
	const workflow = ".github/workflows/create-release.yaml"
	var globs []string
	for _, m := range releaseAsset.FindAllStringSubmatch(readRepoFile(t, workflow), -1) {
		globs = append(globs, m[1])
	}
	if len(globs) == 0 {
		t.Fatalf("found no release assets in %s", workflow)
	}
	published := func(name string) bool {
		for _, g := range globs {
			if ok, _ := path.Match(g, name); ok {
				return true
			}
		}
		return false
	}

	for _, path := range []string{"README.md", "llms.txt", "skills/certtool/SKILL.md"} {
		doc := readRepoFile(t, path)
		for _, m := range downloadAsset.FindAllStringSubmatch(doc, -1) {
			if !published(m[1]) {
				t.Errorf("%s links to %s, which the release workflow does not publish", path, m[1])
			}
		}
		for _, m := range namedAsset.FindAllStringSubmatch(doc, -1) {
			if !published(m[1]) {
				t.Errorf("%s names the release file %s, which the release workflow does not publish", path, m[1])
			}
		}
	}
}
