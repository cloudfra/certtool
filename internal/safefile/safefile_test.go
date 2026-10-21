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

package safefile

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestWrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.key")
	if err := Write(path, []byte("secret"), 0o600); err != nil {
		t.Fatalf("Write() err = %v", err)
	}
	assertFile(t, path, "secret", 0o600)
	assertOnlyFile(t, path)
}

// An existing file keeps its permissions with os.WriteFile; Write must not, or
// a regenerated private key could be world-readable.
func TestWriteTightensExistingPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.key")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil { //nolint:gosec // The test needs a world-readable file to replace.
		t.Fatal(err)
	}

	if err := Write(path, []byte("new"), 0o600); err != nil {
		t.Fatalf("Write() err = %v", err)
	}
	assertFile(t, path, "new", 0o600)
}

func TestWriteSetsRequestedMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.cert")
	if err := Write(path, []byte("cert"), 0o644); err != nil {
		t.Fatalf("Write() err = %v", err)
	}
	assertFile(t, path, "cert", 0o644)
}

// A symlink at the destination must be replaced, never written through.
func TestWriteReplacesSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("untouched"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "app.key")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("cannot create symlinks here: %v", err)
	}

	if err := Write(link, []byte("secret"), 0o600); err != nil {
		t.Fatalf("Write() err = %v", err)
	}
	assertFile(t, target, "untouched", 0o600)
	info, err := os.Lstat(link)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		t.Errorf("%s is still a symlink, want a regular file", link)
	}
	assertFile(t, link, "secret", 0o600)
}

// A symlink to a file that does not exist yet must not create that file.
func TestWriteDoesNotCreateSymlinkTarget(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "victim")
	link := filepath.Join(dir, "app.key")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("cannot create symlinks here: %v", err)
	}

	if err := Write(link, []byte("secret"), 0o600); err != nil {
		t.Fatalf("Write() err = %v", err)
	}
	if _, err := os.Lstat(target); !os.IsNotExist(err) {
		t.Errorf("%s was created through the symlink (stat err = %v)", target, err)
	}
}

func TestWriteRelativePath(t *testing.T) {
	t.Chdir(t.TempDir())
	if err := Write("app.key", []byte("secret"), 0o600); err != nil {
		t.Fatalf("Write() err = %v", err)
	}
	assertFile(t, "app.key", "secret", 0o600)
}

func TestWriteErrors(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "missing", "app.key")
	if err := Write(missing, []byte("x"), 0o600); err == nil {
		t.Error("Write() into a missing directory err = nil, want an error")
	}
	sub := filepath.Join(dir, "sub")
	if err := os.Mkdir(sub, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := Write(sub, []byte("x"), 0o600); err == nil {
		t.Error("Write() over a directory err = nil, want an error")
	}
	if entries, err := os.ReadDir(sub); err != nil || len(entries) != 0 {
		t.Errorf("ReadDir(%s) = %v, %v; want it empty", sub, entries, err)
	}
}

func assertFile(t *testing.T, path, want string, perm os.FileMode) {
	t.Helper()

	got, err := os.ReadFile(path) //nolint:gosec // path is a file the test created.
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Errorf("%s = %q, want %q", path, got, want)
	}
	if runtime.GOOS == "windows" {
		return
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != perm {
		t.Errorf("%s has mode %o, want %o", path, info.Mode().Perm(), perm)
	}
}

// assertOnlyFile fails if the directory of path holds anything but path, such
// as a leftover temporary file.
func assertOnlyFile(t *testing.T, path string) {
	t.Helper()

	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != filepath.Base(path) {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("directory holds %v, want only %s", names, filepath.Base(path))
	}
}
