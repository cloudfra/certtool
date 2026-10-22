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

package certtool

import (
	"os"
	"strings"
	"testing"

	certlib "github.com/cloudfra/certtool/pkg/certtool"
)

func TestValidateModesCAConstraints(t *testing.T) {
	for name, tc := range map[string]struct {
		set  func(*Args)
		want string
	}{
		"without a CA":         {func(a *Args) { a.MaxPathLen = 0 }, "need --ca or --yubikey-generate-root"},
		"domains without a CA": {func(a *Args) { a.PermittedDNSDomains = "example.com" }, "need --ca or --yubikey-generate-root"},
		"with chain":           {func(a *Args) { a.CA, a.Chain, a.PermittedIPRanges = true, "1,1", "10.0.0.0/8" }, "set maxPathLen, permittedDNSDomains, and permittedIPRanges in the spec instead"},
		"negative":             {func(a *Args) { a.CA, a.MaxPathLen = true, -2 }, "--max-path-len must be 0 or more"},
	} {
		t.Run(name, func(t *testing.T) {
			args := DefaultArgs()
			tc.set(&args)
			if err := validateModes(args); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("validateModes() err = %v, want it to contain %q", err, tc.want)
			}
		})
	}

	args := DefaultArgs()
	args.YubiKeyGenerateRoot, args.MaxPathLen, args.PermittedDNSDomains = true, 1, "example.com"
	if err := validateModes(args); err != nil {
		t.Errorf("validateModes() with --yubikey-generate-root err = %v, want nil", err)
	}
}

func TestRunCAConstraints(t *testing.T) {
	root := testArgs(t)
	root.CA, root.MaxPathLen, root.PermittedDNSDomains, root.PermittedIPRanges = true, 0, "example.com", "10.0.0.0/8"
	if err := Run(t.Context(), root); err != nil {
		t.Fatalf("Run() for the root err = %v", err)
	}
	data, err := os.ReadFile(root.PublicCertificate)
	if err != nil {
		t.Fatal(err)
	}
	cert, _, err := certlib.ReadKeyPair(data, mustRead(t, root.PrivateKey))
	if err != nil {
		t.Fatal(err)
	}
	if !cert.MaxPathLenZero || len(cert.PermittedDNSDomains) != 1 || len(cert.PermittedIPRanges) != 1 {
		t.Errorf("root = path length %d (zero %t), domains %v, ranges %v; want 0, [example.com], [10.0.0.0/8]", cert.MaxPathLen, cert.MaxPathLenZero, cert.PermittedDNSDomains, cert.PermittedIPRanges)
	}

	leaf := testArgs(t)
	leaf.ParentPublicCertificate, leaf.ParentPrivateKey, leaf.Hostnames = root.PublicCertificate, root.PrivateKey, "api.example.com,10.0.0.1"
	if err := Run(t.Context(), leaf); err != nil {
		t.Errorf("Run() for a leaf within the constraints err = %v", err)
	}

	for name, set := range map[string]func(*Args){
		"intermediate": func(a *Args) { a.CA = true },
		"other domain": func(a *Args) { a.Hostnames = "evil.com" },
	} {
		t.Run(name, func(t *testing.T) {
			child := testArgs(t)
			child.ParentPublicCertificate, child.ParentPrivateKey = root.PublicCertificate, root.PrivateKey
			set(&child)
			if err := Run(t.Context(), child); err == nil {
				t.Error("Run() err = nil, want the root's constraints to refuse it")
			}
		})
	}
}

func TestRunInvalidPermittedIPRanges(t *testing.T) {
	args := testArgs(t)
	args.CA, args.PermittedIPRanges = true, "10.0.0.0"
	if err := Run(t.Context(), args); err == nil || !strings.Contains(err.Error(), "--permitted-ip-ranges: permitted IP range \"10.0.0.0\"") {
		t.Errorf("Run() err = %v, want an error naming --permitted-ip-ranges", err)
	}
}

func TestRunExportSpecCAConstraints(t *testing.T) {
	args := testArgs(t)
	args.CA, args.MaxPathLen, args.PermittedDNSDomains = true, 1, "example.com"
	args.ExportSpec = t.TempDir() + "/out.yaml"
	if err := Run(t.Context(), args); err != nil {
		t.Fatalf("Run() err = %v", err)
	}
	specs, err := certlib.ReadSpec(args.ExportSpec)
	if err != nil {
		t.Fatal(err)
	}
	if specs[0].MaxPathLen == nil || *specs[0].MaxPathLen != 1 || len(specs[0].PermittedDNSDomains) != 1 {
		t.Errorf("exported spec = %+v, want maxPathLen 1 and permittedDNSDomains [example.com]", specs[0])
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()

	data, err := os.ReadFile(path) //nolint:gosec // path is a file the test created.
	if err != nil {
		t.Fatal(err)
	}
	return data
}
