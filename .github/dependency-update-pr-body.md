# Weekly dependency refresh

Produced by `scripts/update-project.sh`, run on the weekly schedule in
`.github/workflows/dependency-update.yaml`.

- Toolchain and tool pins in the `Makefile_*.mk` files, resolved from each
  tool's authoritative source (GitHub releases, the HashiCorp releases API,
  or the Go module proxy).
- Terraform provider pins and `required_version` under `install/terraform`.
- Vendored protos under `third_party/`.
- `go.mod`.

The script leaves changes in the working tree without committing, so this
PR is the review point. Merging it is a human decision.
