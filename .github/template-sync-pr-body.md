# Template-managed files re-synced from upstream

Produced by `scripts/sync-template.sh`, run on the Friday-night schedule
in `.github/workflows/template-sync.yaml`. It replaces this project's
template-managed files with the current versions from template-go's
`main` branch:

- every `Makefile_*.mk` (the root `Makefile` and
  `Makefile_testassets.mk` are preserved),
- every root dotfile config (`.gitignore`, `.golangci.yml`,
  `.yamllint.yml`, ...),
- the whole `.github/` directory.

Files upstream no longer ships are deleted and files it now ships are
added, so the diff is the whole gap since the last sync rather than a
merge. The script is safe to re-run: it converges on the upstream tree.

## This is a hard replace - read the diff before merging

Any local edit to a managed file is discarded by the sync, and this PR is
where that becomes visible. Check the diff for:

- Project-specific edits under `.github/` - workflow triggers, build
  matrix, artifact names. `deploy.yaml` names its release artifacts
  after `ALL_APPS` in the root `Makefile`, so a consumer project's
  `exampleapp-*` to `<app>-*` rename is reverted by the sync and has to
  be re-applied before merging.
- Customized root dotfiles - `.gitignore` entries for local paths, lint
  config tweaks.

The per-project CI hooks are the exception and are never overwritten:
`scripts/prepare-ci.sh` and `scripts/Initialize-CI.ps1` are copied in
only when missing, so a project's customization of them survives every
sync. They live under `scripts/`, which the sync does not otherwise
touch.

Nothing here merges automatically - merging is a human decision.
