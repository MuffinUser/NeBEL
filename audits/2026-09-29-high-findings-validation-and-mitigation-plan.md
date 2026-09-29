# Validation and Mitigation Plan: High-Priority Findings from the 2026-09-29 Repository Analysis

Source audit: [2026-09-29-repository-analysis.md](2026-09-29-repository-analysis.md) (untracked in the working copy at the time of this writing; not present on this branch — refer to the copy in the main checkout).

This document verifies the seven findings marked "Hoch" (High) in that audit — P01 through P07 — directly against the current source in this repository, assesses whether "High" is justified, and lays out a phased mitigation plan with effort estimates.

## 1. Verification method

Each finding was independently re-derived by reading the cited source files at their current line numbers (which had drifted slightly since the audit), not merely by trusting the audit's prose. P02 was additionally verified empirically by parsing the exact reproduction input through the actual `goccy/go-yaml` parser used by this codebase. Two follow-up checks (the `filter.nebel.required` git setting, and smudge behavior for untagged plaintext in a protected field) were done afterward because they materially change the mitigation plan's phasing.

## 2. Verdict summary

| ID | Verdict | Notes |
|---|---|---|
| P01 | **Confirmed** | Common-path operational bug, not attacker-driven. Re-running `init` unconditionally deletes and restores managed files from HEAD with no dirty check. |
| P02 | **Confirmed (empirically)** | Quote-unaware comment truncation in YAML span computation leaks a plaintext suffix of a quoted secret into the git blob. |
| P03 | **Confirmed** | Dotted key collisions (`"a.b"` vs. nested `a: {b: ...}`) silently resolve to the wrong field with no error. |
| P04 | **Confirmed, worse than stated** | Duplicate JSON keys leave the second occurrence in plaintext — and standard `encoding/json` map-unmarshal takes the *last* duplicate, meaning most consumers would actually use the plaintext value, not the encrypted one. |
| P05 | **Confirmed, narrower in practice** | Type metadata is genuinely outside the AEAD's authenticated data, so `type:str → type:bool` tampering passes authentication. However, smudge already passes through *any* untagged plaintext in a protected field with no error at all (`filterop.go:210`, intentional for migration, AC-6.7) — so an attacker with blob write access doesn't need the type-confusion trick; they can just substitute plaintext directly. P05's real distinguishing value is stealth (a type-flipped field still displays as `ENC[...]` in review) rather than reach. |
| P06 | **Confirmed** | The derived key is base64-encoded and passed as a literal `git config` subprocess argument — inconsistent with this codebase's own established threat model, which already refuses password arguments on its own CLI for the identical reason (argv is readable via `/proc/<pid>/cmdline`). |
| P07 | **Confirmed, all 3 sub-issues** | (1) `*.env`-style root-only vs. recursive `.gitattributes` glob semantics diverge silently; (2) unescaped filenames with spaces break `.gitattributes` field parsing; (3) `doublestar.Match`'s error is discarded in `MatchRule`, so a malformed hand-edited glob silently never matches. |

**All seven High findings stand.** None should be downgraded; P04 arguably deserves more weight than the audit gave it, and P05 should be read together with the smudge-passthrough gap noted above rather than in isolation.

## 3. A structural fact that changes the plan

`filter.nebel.required` is set to `true` at registration (`cmd/nebel/init.go:356`). This means git already treats a *failing* clean/smudge filter invocation as a hard error that blocks the operation (e.g. blocks `git add`/commit). Several of the cheapest mitigations below are "detect the bad case and return an error" rather than "detect and gracefully recover" — and because of `required=true`, those errors will actually be enforced by git, not just logged. This makes P03, P04, and P07(1)/(3) considerably cheaper to fix well than a full silent-recovery design would be.

## 4. Phased mitigation plan

### Phase 0 — Immediate, no code change (do now, in parallel with everything else)

- **For any real installation already using nebel to protect live secrets:** scan the raw stored blobs of protected paths, including history (`git cat-file -p <rev>:<path>` bypasses the smudge filter and shows exactly what's stored), for plaintext remnants matching the P02/P03/P04/P07/P08 patterns. Any secret found must be rotated at its source — nebel's own key rotation does not un-expose an already-leaked plaintext. This is the natural first justification for the audit's separately-noted missing `nebel status` command.
- Unrelated to the audit, but found while validating this plan: `git remote -v` in this repository currently resolves to a URL with a **live GitHub PAT embedded in plaintext**. Recommend rotating that token and switching to a credential helper immediately.

### Phase 1 — Quick, non-breaking, fail-fast hardening (~3–4 developer-days total, incl. tests)

| Item | Fix | Effort |
|---|---|---|
| P01 | Add a dirty-check (`git status --porcelain` / `git diff --quiet HEAD --` over managed files) before `gitutil.CheckoutAll`'s remove+checkout; abort with a clear error if any managed file has uncommitted changes. Single function (`gitutil.go`), reuse existing e2e test infra. Must not block a legitimate first `init` on a clean clone — needs a test for that path specifically. | 3–5h |
| P04 | Detect a second key matching the target path within the same JSON object in `descendObject`/`cleanValues`; hard-error instead of silently encrypting only the first. Small, contained change. | 2–4h |
| P07 (1)+(3) | Single high-leverage fix: make `Clean` (`filterop.go:57-61`) return an error when git invokes it for a path that matches no configured rule, instead of silently passing plaintext through. Because `required=true`, this blocks the commit. Also stop discarding `doublestar.Match`'s error in `MatchRule` and surface it as a hard error. This neutralizes both sub-issues without needing to reconcile nebel's glob semantics with `.gitattributes` semantics (that reconciliation becomes a pure usability improvement afterward, not a security fix). | 3–5h combined |
| P06 | Stop passing the derived key via `git config` subprocess argv. Either write directly to `.git/config` (resolve the real location via `git rev-parse --git-common-dir` to handle linked worktrees, respect `config.lock`), or — simpler and also addresses the audit's separate "harden local key storage" note — use a dedicated key file with `0600` permissions, with a fallback read path for the old config-based storage. | 4–8h |
| P05 (stopgap only) | On smudge, reject a decrypted value whose literal text isn't syntactically valid for its claimed type before rendering it unquoted (e.g. refuse to render `"not-a-bool"` as `type:bool`). Narrows the injection tail risk; does not close the underlying authentication gap. | 2–4h |

### Phase 2 — Medium, non-breaking format-preserving fixes (~2–3 developer-days)

| Item | Fix | Effort |
|---|---|---|
| P02 | Make `scalarText`/`yamlSpan` quote-aware: only truncate at an unquoted `#`/` #`; leave quoted, literal, and folded scalar spans untouched. Needs new tests for quoted strings containing `#`, block scalars, and CRLF combinations. Touches every YAML span computation — moderate regression risk, needs solid coverage before merge. | 1–2 days |
| P03 | Add path-collision detection: hard-error when a flattened dotted path is ambiguous with a nested path in the same document, rather than silently resolving to one of them. (Full escaping syntax for literal dots in key names is a larger, separate feature — recommend deferring unless real users actually hit this, ~2–3 additional days if needed later.) | 4–8h |
| P07 (2) | Validate/reject or escape pattern/filename characters (spaces, etc.) before writing an `.gitattributes` line at `add file` time. | 2–3h |

### Phase 3 — Breaking format change, needs versioning and migration (~3–5 developer-days)

| Item | Fix | Effort |
|---|---|---|
| P05 (proper fix) | Bind `type` into the AEAD's authenticated data (or into the authenticated plaintext itself) so tampering the type metadata fails authentication. This changes the ciphertext/tag format: every previously-committed tag was authenticated without type, so this needs a new tag/format version, backward-compatible decryption of old tags, and a migration path analogous to the existing key-rotation mechanism (spec 11). | 3–5 days incl. migration tooling and docs |

### Design question to resolve with stakeholders, not purely a bug fix

Smudge currently passes through *any* untagged plaintext in a protected field with no error at all, intentionally, to support gradual migration (AC-6.7). This is the more foundational relative of P05 and is a known limitation shared by filter-driven transparent-encryption tools generally (nebel, like git-crypt or unsigned sops usage, does not by itself defend against a git committer with write access substituting content — that requires signed commits / branch protection, outside this tool's scope). Worth an explicit "strict mode" option that fails smudge/status on an untagged protected field, opt-in so existing migration workflows keep working. This is a scope/product decision, not included in the effort estimates above.

## 5. Total effort estimate

- Phase 1: ~3–4 developer-days
- Phase 2: ~2–3 developer-days
- Phase 3: ~3–5 developer-days

**Total: roughly 8–12 developer-days (1.5–2.5 weeks) for one engineer**, before touching the audit's medium-priority items (P08–P12), which were out of scope for this validation pass.
