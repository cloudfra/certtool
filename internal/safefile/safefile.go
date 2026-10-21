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

// Package safefile writes files that may hold secrets, such as private keys.
//
// Each file is written to a new temporary file in the same directory, which is
// then renamed over the destination. So, unlike os.WriteFile:
//   - the destination always ends up with the intended mode, even when it
//     already existed with looser permissions;
//   - a symbolic link at the destination is replaced, not followed, so the
//     data is never written to wherever the link points;
//   - readers see either the old file or the complete new one, never a
//     partial write.
package safefile

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const (
	privateMode os.FileMode = 0o600
	publicMode  os.FileMode = 0o644
)

// WritePrivate replaces path with data that only its owner may read, such as a
// private key, a PKCS#12 bundle, or a spec holding a password.
func WritePrivate(path string, data []byte) error {
	return write(path, data, privateMode)
}

// WritePublic replaces path with data that anyone may read, such as a
// certificate.
func WritePublic(path string, data []byte) error {
	return write(path, data, publicMode)
}

func write(path string, data []byte, perm os.FileMode) error {
	dir, base := filepath.Split(path)
	if dir == "" {
		dir = "."
	}
	if info, err := os.Lstat(path); err == nil && info.IsDir() {
		return fmt.Errorf("cannot write %s: it is a directory", path)
	}

	// CreateTemp opens the file with O_EXCL and mode 0600, so no other user can
	// read it while it is being written.
	tmp, err := os.CreateTemp(dir, "."+base+".tmp-*")
	if err != nil {
		return fmt.Errorf("cannot create a temporary file for %s: %w", path, err)
	}
	if err := fill(tmp, data, perm); err != nil {
		return errors.Join(fmt.Errorf("cannot write %s: %w", path, err), removeTemp(tmp.Name()))
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return errors.Join(fmt.Errorf("cannot replace %s: %w", path, err), removeTemp(tmp.Name()))
	}
	return nil
}

// fill writes data to f, gives it mode perm, flushes it to disk, and closes it.
// f is closed even when an earlier step fails.
func fill(f *os.File, data []byte, perm os.FileMode) error {
	if _, err := f.Write(data); err != nil {
		return errors.Join(err, f.Close())
	}
	if err := f.Chmod(perm); err != nil {
		return errors.Join(fmt.Errorf("cannot set the file mode: %w", err), f.Close())
	}
	if err := f.Sync(); err != nil {
		return errors.Join(err, f.Close())
	}
	return f.Close()
}

func removeTemp(name string) error {
	if err := os.Remove(name); err != nil {
		return fmt.Errorf("cannot remove the temporary file %s: %w", name, err)
	}
	return nil
}
