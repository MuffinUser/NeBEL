# Spec 10 — Cross-platform build

See REQUIREMENTS.md § Cross-platform support.

## Acceptance criteria

- **AC-10.1**: a build for `linux/amd64` and `linux/arm64` produces a
  statically-linked binary (`CGO_ENABLED=0`) with no dynamic dependency
  beyond baseline glibc — runs correctly inside a minimal UBI container
  with no additional packages installed.
- **AC-10.2**: equivalent builds succeed for `darwin/amd64`,
  `darwin/arm64`, and `windows/amd64`.
- **AC-10.3**: a smoke test runs on each target platform in CI: build the
  binary, run `nebel init` + `add` + a round-trip `git add`/checkout
  in a scratch repo, verify decrypted content matches the original.
- **AC-10.4**: all cross-compiled binaries are produced from a single Go
  toolchain invocation per target (no per-platform build environment
  required), matching the "single machine, no toolchain setup" rationale
  for choosing Go.
