# Certificate Hierarchy Generation

Generate a full chain of trust (Root CA, optional intermediates, leaf) in a single invocation.

## Modes

### Quick mode: `--chain N`

Generates N certificates forming a linear chain. Depth 0 is the root CA, depths 1..N-2 are intermediate CAs, depth N-1 is the leaf.

```bash
certtool --chain 3 --hostnames myserver.com --output-dir certs/
```

All certificates inherit the same `--key-type`, `--organization`, `--country`, and other subject flags from the CLI. CAs get auto-generated CommonNames:

- Depth 0: `"<Organization> Root CA"`
- Depth 1..N-2: `"<Organization> Intermediate CA <i>"`
- Depth N-1: uses `--common-name` (or defaults to `--organization`)

Constraints:

- `--chain` must be >= 2 (root + leaf minimum).
- Cannot be combined with `--hierarchy` or `--parent-public-certificate`.

### Full control: `--hierarchy file.yaml`

Reads a YAML file defining a tree of certificates.

```bash
certtool --hierarchy chain.yaml --output-dir certs/
```

Constraints:

- Cannot be combined with `--chain` or `--parent-public-certificate`.
- Top-level list must have exactly one element (the root) with `ca: true`.
- Every node with `children` must have `ca: true`.

## YAML Schema

```yaml
- cn: "My Root CA"            # CommonName (required)
  ca: true                    # Is this a CA? (default: false)
  key-type: "RSA-2048"        # Optional, inherits from parent node or CLI --key-type
  validity: "87600h"          # Optional Go duration, inherits from parent node or CLI --validity
  organization: "ACME"        # Optional, inherits from parent node or CLI --organization
  country: "US"               # Optional, inherits from parent node or CLI --country
  hostnames:                  # SANs (typically leaf-only)
    - myserver.com
  ports: [443, 8443]          # Port expansion on hostnames
  filename: "root"            # Optional basename override (no extension) -> root.cert + root.key
  children:                   # Certificates signed by this node
    - cn: "leaf.example.com"
      hostnames:
        - leaf.example.com
```

All fields except `cn` are optional. Unspecified fields inherit from the parent node, falling back to CLI defaults.

## Output Filenames

### Default naming

Derived from the chain of ancestor CNs, slugified (lowercased, non-alphanumeric replaced with `-`, collapsed) and joined with `-`:

- Root `CN=My Root CA` -> `my-root-ca.cert` + `my-root-ca.key`
- Its child `CN=Intermediate CA` -> `my-root-ca-intermediate-ca.cert`
- Its child `CN=myserver.com` -> `my-root-ca-intermediate-ca-myserver-com.cert`

### Explicit override

The `filename` field in YAML provides a complete basename override (no extension). It replaces the entire chain-path convention for that node:

```yaml
filename: "server"  # -> server.cert + server.key
```

A `filename` override does NOT affect children's default names. Children still derive their chain-path from the ancestor CNs, not from `filename` overrides.

### Output directory

All files are written to `--output-dir` (default: current directory). The directory is created if it does not exist.

### `--chain N` naming

Uses the same slugified-chain convention with auto-generated CNs. For `--chain 3 --organization ACME`:

- `acme-root-ca.cert`
- `acme-root-ca-acme-intermediate-ca-1.cert`
- `acme-root-ca-acme-intermediate-ca-1-acme.cert`

## New Code

### `pkg/certtool/hierarchy.go`

New file containing:

- `HierarchyNode` struct -- the YAML schema. Fields: `CN`, `CA`, `KeyType`, `Validity`, `Organization`, `Country`, `Hostnames`, `Ports`, `Filename`, `Children`.
- `HierarchyOutput` struct -- result per node: `Node` identity, `KeyPair`, `CertPath`, `KeyPath`.
- `ParseHierarchyFile(path string) ([]HierarchyNode, error)` -- reads and validates YAML.
- `GenerateHierarchy(nodes []HierarchyNode, defaults *Args, outputDir string) ([]HierarchyOutput, error)` -- recursive depth-first generation. Each node calls `GenerateKeyPair` with the parent's `KeyPair` set as `ParentKeyPair`. Collects results and writes files.
- `ChainToHierarchy(depth int, args *Args) []HierarchyNode` -- converts `--chain N` into `[]HierarchyNode` so both modes share the same generation path.
- `slugify(s string) string` -- helper to convert CN to filename-safe slug.

### `pkg/certtool/hierarchy_test.go`

Tests that parse the example YAML files and verify generated certificates:

- Issuer DN matches parent's subject DN.
- `cert.CheckSignatureFrom(parent)` passes for each parent-child pair.
- CA certs have `IsCA: true` and `KeyUsageCertSign`.
- Leaf certs have correct SANs and `IsCA: false`.
- Output file count matches expected node count.
- Filename generation matches expected chain-path convention.
- Explicit `filename` override works.

### `cmd/certtool/certtool.go`

Adds three new flags:

- `--chain int` (default 0, meaning disabled)
- `--hierarchy string` (default "", meaning disabled)
- `--output-dir string` (default ".")

Mutual exclusivity validation in `certtoolMain()`: at most one of `--chain`, `--hierarchy`, or normal single-cert mode. Error if combined with `--parent-public-certificate`.

### Example files

- `examples/simple-chain.yaml` -- Root CA + leaf (equivalent to `--chain 2`).
- `examples/three-tier.yaml` -- Root CA + intermediate CA + leaf.
- `examples/multi-leaf.yaml` -- Root CA with two leaf children (branching).

Each example is loaded by tests in `hierarchy_test.go` to verify it produces valid certificate chains.

## Validation Rules

1. `--chain` must be >= 2.
2. YAML top-level must be a single-element list with `ca: true`.
3. Every node with `children` must have `ca: true`.
4. `cn` is required on every node.
5. `--chain`/`--hierarchy` cannot be combined with each other or with `--parent-public-certificate`.
6. Output filenames must not collide within a single hierarchy (error if two nodes resolve to the same path).

## YAML Dependency

The project does not currently import a YAML library directly. This feature adds `gopkg.in/yaml.v3` (already present in `go.sum` as a transitive dependency of `go.uber.org/zap`).
