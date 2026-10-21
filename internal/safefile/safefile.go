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
package safefile

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Write replaces path with data and gives it mode perm.
//
// The data is written to a new temporary file in the same directory, which is
// then renamed over path. So, unlike os.WriteFile:
//   - path always ends up with mode perm, even when it already existed with
//     looser permissions;
//   - a symbolic link at path is replaced, not followed, so the data is never
//     written to wherever the link points;
//   - readers see either the old file or the complete new one, never a
//     partial write.
func Write(path string, data []byte, perm os.FileMode) (err error) {
	dir, base := filepath.Split(path)
	if dir == "" {
		dir = "."
	}
	if info, statErr := os.Lstat(path); statErr == nil && info.IsDir() {
		return fmt.Errorf("cannot write %s: it is a directory", path)
	}

	// CreateTemp opens the file with O_EXCL and mode 0600, so no other user can
	// read it while it is being written.
	tmp, err := os.CreateTemp(dir, "."+base+".tmp-*")
	if err != nil {
		return fmt.Errorf("cannot create a temporary file for %s: %w", path, err)
	}
	defer func() {
		if err != nil {
			_ = tmp.Close() //nolint:errcheck // The write already failed; that error is the one to report.
			if removeErr := os.Remove(tmp.Name()); removeErr != nil {
				err = errors.Join(err, fmt.Errorf("cannot remove the temporary file: %w", removeErr))
			}
		}
	}()

	if _, err = tmp.Write(data); err != nil {
		return fmt.Errorf("cannot write %s: %w", path, err)
	}
	if err = tmp.Chmod(perm); err != nil {
		return fmt.Errorf("cannot set the permissions of %s: %w", path, err)
	}
	if err = tmp.Sync(); err != nil {
		return fmt.Errorf("cannot write %s: %w", path, err)
	}
	if err = tmp.Close(); err != nil {
		return fmt.Errorf("cannot write %s: %w", path, err)
	}
	if err = os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("cannot replace %s: %w", path, err)
	}
	return nil
}
