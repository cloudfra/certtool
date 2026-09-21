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

package certtool_test

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/cloudfra/certtool/pkg/certtool"
)

// Run does everything the certtool command does, so a program can offer the
// same features behind its own front end: fill in Options, however the values
// were obtained, and call Run.
func ExampleRun() {
	dir, err := os.MkdirTemp("", "certtool-example")
	if err != nil {
		log.Fatal(err)
	}

	opts := certtool.DefaultOptions()
	opts.Chain = "1,1" // a root CA and one leaf
	opts.CommonName = "svc"
	opts.OutputDir = dir

	if err := certtool.Run(opts); err != nil {
		log.Fatal(err)
	}

	certs, err := filepath.Glob(filepath.Join(dir, "*.cert"))
	if err != nil {
		log.Fatal(err)
	}
	for _, cert := range certs {
		fmt.Println(filepath.Base(cert))
	}

	if err := os.RemoveAll(dir); err != nil {
		log.Fatal(err)
	}
	// Output:
	// cloudfra-root-ca-svc.cert
	// cloudfra-root-ca.cert
}
