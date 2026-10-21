# AGENTS.md

Guidance for AI coding agents working in this repository. To *use* certtool rather than change it, read [skills/certtool/SKILL.md](skills/certtool/SKILL.md).

## What this is

certtool is a Go CLI and library (`github.com/cloudfra/certtool`) that generates X.509 certificates and keys: self-signed TLS, CA hierarchies, code signing (`.pfx`), and roots kept on a YubiKey. It runs in automation.

## Layout

| Path | Contents |
| ---- | -------- |
| `cmd/certtool` | `main`: parses flags into `certtool.Args` and calls `certtool.Run`. Nothing else belongs here. |
| `internal/certtool` | `Args`, `DefaultArgs`, `Run`, flag validation, and the modes (single, `--chain`, `--spec`, `--export-spec`, YubiKey). |
| `internal/logging` | zap-backed `slog` logger writing to stderr. |
| `pkg/certtool` | Public library: certificate generation, specs, profiles, PKCS#12. |
| `pkg/yubikey` | YubiKey PIV issuer. `yubikey_piv.go` is the real implementation, `yubikey_stub.go` the fallback for builds without PC/SC. |
| `pkg/certtool/testdata` | Example specs, also used by tests and docs. |
| `docs/` | `spec.md` and `use-cases/` guides. |
| `skills/certtool` | Agent skill for using the CLI, shipped as a Claude Code plugin through `.claude-plugin/`. |

## Commands

```bash
make test-go                 # unit tests
go test -race ./...          # quick loop
make lint-go                 # gofmt, gofumpt, golangci-lint, revive
make lint-markdown           # rumdl
make presubmit               # everything CI runs
```

Also lint the other build variants after touching `pkg/yubikey` or build tags:

```bash
GOOS=windows build/toolchain/bin/golangci-lint run ./...
CGO_ENABLED=0 build/toolchain/bin/golangci-lint run ./...
```

The real YubiKey code builds on Windows without cgo and elsewhere with `CGO_ENABLED=1` and PC/SC headers (`libpcsclite-dev`). Without them only the stub builds.

## Rules

- **Never prompt.** certtool runs unattended. A missing input is an error that names the flag (and environment variable, if any) and says why it is needed. The only wait allowed is the YubiKey touch.
- **Errors name flags.** Write `--flag-name` in error messages so the user knows what to change.
- **New flag:** add a field to `Args`, its default to `DefaultArgs`, the binding in `cmd/certtool/certtool.go`, a case in `TestParseFlags`, and document it in `README.md` and `skills/certtool/references/flags.md`. `TestSkillFlags` fails if the skill names a flag that does not exist or leaves one out.
- **Tests never touch a real YubiKey.** Use the fakes in `pkg/yubikey/fake_test.go`, or select serial `1`, which no device has.
- **Docs are tested.** Every YAML block in `docs/spec.md` and the skill's spec reference must parse as a spec. Keep examples runnable.
- New Go files start with the Apache 2.0 license header used in the existing files.
