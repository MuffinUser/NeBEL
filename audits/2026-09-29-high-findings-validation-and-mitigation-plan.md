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

## 3. Priority order — what to fix first, and what to bundle together

Ranked by importance to the tool's core promise (protecting secrets), not by implementation effort. The distinguishing question at each tier: does this bug leak the secret itself, or something weaker (the key, or integrity of already-protected data)? Within "leaks the secret" bugs, does it leak silently while reporting success (worst — false sense of security), and how easily does a normal user trigger it without doing anything unusual?

**Tier 1 — Silent, complete plaintext exposure while the tool reports success.** These are the worst class of bug for an encryption tool: nothing looks wrong, but the secret is fully unprotected in the git blob.

1. **P07(1)** — root-only vs. recursive glob mismatch. Highest priority of all: triggered by the single most natural pattern a user would write (`*.env`-style, exactly like `.gitignore` habits) combined with the equally common case of the file living in a subdirectory. `add file` reports success; git invokes the filter; nebel's own matcher silently disagrees and lets plaintext through.
2. **P04** — duplicate JSON keys. Full exposure of exactly the value most JSON consumers will actually use (last-write-wins on unmarshal), while the encrypted first copy is decoration.
3. **P03** — dotted path collision. Full exposure of the intended field; requires a specific naming collision, so somewhat less likely to occur than P07(1)/P04, but total when it does.
4. **P07(3)** — discarded glob-match errors. A malformed hand-edited rule silently protects nothing; requires manual `.gitattributes`/config editing to trigger, so lower likelihood than the above, same total impact.
5. **P07(2)** — unescaped filenames with spaces. Narrower trigger condition (spaces in filenames), same silent-total-bypass outcome.

**Tier 2 — Large partial plaintext exposure.**

6. **P02** — YAML quoted-string comment truncation. Not silent-total like Tier 1, but close in practice: in the audit's own example, only the first 4 characters end up encrypted and nearly the entire rest of the secret is left as plaintext. Triggers on any secret value containing a literal `" #"`, which is plausible for real passwords/tokens/connection strings.

**Tier 3 — Data loss, not a leak.** Different axis entirely (destroys the user's own work, doesn't expose a secret to a third party), but ranked here because it's trivially easy to trigger with completely ordinary use — no attacker, no unusual input required.

7. **P01** — re-running `init` destroys uncommitted/staged changes to managed files.

**Tier 4 — Conditional local exposure, requires an additional attacker capability.**

8. **P06** — derived key visible via process argument list. Only exploitable by a co-located observer who can already read another user's/process's argv (shared host, container escape, etc.) — a real gap and inconsistent with the tool's own stated threat model, but requires more attacker capability than "can read the git repo," which is all Tiers 1–3 require.

**Tier 5 — Integrity-only, and largely redundant with an accepted design gap.**

9. **P05** — type metadata not authenticated. Real, but as noted in §2, an attacker with the blob-write access this requires can already substitute plaintext directly via the pre-existing, intentional smudge passthrough — so this doesn't expand what such an attacker can already do, it only makes one specific form of tampering (type-flip) harder to spot in review.

### What to fix together

- **Package A — "filter/rule matching correctness" (P07(1), P07(2), P07(3)):** same files (`config.go`'s `Validate`/`MatchRule`, `add.go`'s `addGitattributesPattern`, `filterop.go`'s `Clean`), same underlying defect class (a registered rule doesn't actually guarantee git and nebel agree on what's matched), same test setup. Do this as one PR — it's also the single highest-priority fix, so it should be first regardless of grouping.
  - **Status: done** (commit `7acffc9` on branch `worktree-audit-mitigation-plan`). `Clean`/`Smudge` now return `filterop.ErrNoMatchingRule` instead of silently passing content through when no rule matches a path git invoked the filter for; `Config.Validate` rejects a syntactically invalid glob via `doublestar.ValidatePattern`; `addGitattributesPattern` escapes leading `#`/`!` and embedded spaces. A new e2e test reproduces the exact P07(1) scenario (bare `*.env` glob, file in a subdirectory) against a real git repository and was confirmed to fail against the pre-fix code before passing against the fix. Full existing test suite (`go test ./...`) passes unchanged.
- **Package B — "fail-closed field resolution" (P03, P04):** different files (`path.go`/`json.go` vs. the same), but the identical defensive pattern (detect an ambiguous/duplicate field target and hard-error via `required=true` instead of silently protecting only one candidate). Natural to design and review together even though the code changes are in different functions.
  - **Status: done** (commit `081f639` on branch `worktree-audit-mitigation-plan`). Both turned out to be one fix: `Locate` now cross-checks the configured path against the existing `Leaves()` walk and refuses with a new `ErrAmbiguousPath` if more than one leaf shares that path string, before resolving to any of them. This catches P03's literal-dot-vs-nested collision for both formats, and P04's JSON duplicate-key case for free (go-yaml's parser already rejects a literal duplicate YAML key on its own, confirmed empirically — only JSON needed this part). Verified directly against the pre-fix code: it silently returned the wrong/first value with no error in both repro cases. Full existing test suite passes unchanged.
- **Package C — P02 alone**, but worth opening the YAML renderer "under the hood" only once: if this work is scheduled, consider folding in the audit's medium-priority P10 (control characters not escaped) and P11 (multi-document YAML only partially handled) at the same time, since they touch the exact same rendering/parsing code path and the same test harness — doing them separately means paying the review/regression-risk cost of touching `yaml.go`'s scalar handling three times instead of once. (P10/P11 are not part of this High-severity validation pass; flagged here purely as an efficiency note.)
  - **Status: done** (commit `7d63b6f` on branch `worktree-audit-mitigation-plan`; P10/P11 were not folded in — still open). `scalarText` no longer searches a quoted scalar's Origin for a trailing comment at all: verified empirically that a quoted scalar's Origin is always exactly the quoted literal verbatim with no trailing trivia ever folded in, so the search — which was finding a false match *inside* the quotes — is simply skipped for quoted scalars, and kept only for plain scalars, where it's a no-op in practice (the lexer itself can never let " #" survive into a plain scalar's own Origin). Verified directly against the pre-fix code: `Locate` on a quoted value containing " #" returned a 4-byte span while `span.Value` was already the full, correct value — the exact partial-plaintext-leak mechanism.
  - **Bonus finding, not in the original audit:** while fixing this, discovered that literal (`|`) and folded (`>`) block scalars are already silently corrupted by the pre-fix code — `ast.LiteralNode.GetToken()` returns only the block's header token, not its content, so `Locate` would splice a ciphertext tag over the single `|`/`>` character. Confirmed directly against the pre-fix code. Added a new `ErrBlockScalarUnsupported` so this now fails loudly instead; proper block-scalar support remains unimplemented and out of scope here.
- **Package D — P01 alone.** Self-contained (`gitutil.go`/`init.go`), no shared code with the others — can be done in parallel by a different engineer with no coordination cost.
  - **Status: done** (commit `ad0ceb7` on branch `worktree-audit-mitigation-plan`). Added `gitutil.DirtyFiles`, which runs a single `git diff --name-only HEAD -- <files>` to catch staged and unstaged changes alike; `CheckoutAll` now calls it before touching anything and refuses with a new `ErrDirtyManagedFiles` naming every dirty path. Verified directly against the pre-fix code with a standalone probe: an unstaged edit to a managed file was silently destroyed (`CheckoutAll` returned `decrypted=1, failures=nil, err=nil`, and the file's content reverted to HEAD with the edit gone). A clean repo (the ordinary post-`init` case) is confirmed to still succeed normally.
- **Package E — P06, and worth bundling with the audit's separate (non-defect) "harden local key storage" suggestion.** A single fix — a dedicated `0600` key file instead of `git config` — addresses both the argv-exposure bug and that hardening suggestion at once.
  - **Status: done** (commit `8b830ea` on branch `worktree-audit-mitigation-plan`). `localkey.Set` now writes to a new `nebel-keys` file (0600) inside the shared git-common-dir instead of via `git config --local <name> <value>` — closing the subprocess-argv exposure. `Get`/`All` still fall back to the legacy git-config location so an existing clone doesn't need to re-run `nebel init`. Several `cmd/nebel` e2e tests asserted directly on the old git-config storage as their way of checking key registration; updated them (via a new shared `registeredKeyValue` helper) to check the actual current location instead of silently becoming vacuous checks. Verified directly against the pre-fix code: `Set` left the raw base64 key sitting in plain `.git/config` content under `[filter "nebel"] key = ...` — written by exactly the subprocess call this fix removes the key's argument from. Full test suite passes unchanged.
- **Package F — P05, standalone, last.** Breaking ciphertext-format change with its own migration path; do not bundle with anything else, since it needs its own versioned release and rollout communication independent of all other fixes.
  - **Status: done** (commit `ba8e9aa` on branch `worktree-audit-mitigation-plan`). Reused the existing ALGO-field mechanism (spec 03 AC-3.8) rather than inventing a new one: a new `AES256_SIV_TB` identifies a value tag whose type is bound into the AAD; `EncodeValue` always produces this form now, while `Parse` still accepts the legacy `AES256_SIV` form and exposes which one via a new `Tag.TypeBound` field, so `smudgeValues` reconstructs the exact AAD each form was actually encrypted under. No separate migration tooling was needed in the end: `cleanValues` already unconditionally re-encrypts any plaintext field via `EncodeValue`, so a legacy value converges onto the type-bound form the next time anything re-encrypts it (an edit, `nebel rotate`, or `git add --renormalize`) — the same mechanism already used for key-version convergence. A legacy tag's type remains genuinely unauthenticated until that happens; this residual limitation is deliberately documented and tested (`TestSmudgeValuesLegacyTagTypeStillUnauthenticated`), not an oversight. Verified directly against the pre-fix code: a `type:str`→`type:bool` edit on an untouched ciphertext produced no authentication error and rendered the secret unquoted. Full test suite passes unchanged. Also updates `specs/03-value-encoding.md` (new AC-3.10).

Recommended shipping order: **Package A → Package B → Package C → Package D and Package E in parallel → Package F** as a separate, later release.

## 4. A structural fact that changes the plan

`filter.nebel.required` is set to `true` at registration (`cmd/nebel/init.go:356`). This means git already treats a *failing* clean/smudge filter invocation as a hard error that blocks the operation (e.g. blocks `git add`/commit). Several of the cheapest mitigations below are "detect the bad case and return an error" rather than "detect and gracefully recover" — and because of `required=true`, those errors will actually be enforced by git, not just logged. This makes P03, P04, and P07(1)/(3) considerably cheaper to fix well than a full silent-recovery design would be.

## 5. Phased mitigation plan

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

## 6. Total effort estimate

- Phase 1: ~3–4 developer-days
- Phase 2: ~2–3 developer-days
- Phase 3: ~3–5 developer-days

**Total: roughly 8–12 developer-days (1.5–2.5 weeks) for one engineer**, before touching the audit's medium-priority items (P08–P12), which were out of scope for this validation pass.
