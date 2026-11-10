# Plan — field-level encryption for `.env` and `.properties`

Branch: `feature/line-format-value-encryption`
Specs: 05 § Line-based formats (AC-5.9–5.32), 04 AC-4.11, 06 AC-6.14–6.15,
08 AC-8.12.

## Decisions (agreed 2026-10-02)

| Topic | Decision |
|---|---|
| `.env` file names | `*.env`, `.env`, `.env.*`. Detected by base name; a known extension wins (`.env.json` is JSON) |
| Duplicate configured key | Hard error naming the key and lines (`ErrDuplicateKey`) |
| Multi-line values | Tokenized so they're skipped correctly, but locating one is `ErrMultiline` (v1) |
| What gets encrypted | Raw literal: quotes stay in the file, no unescaping; `type:str` |
| `.env` syntax | `export ` prefix supported; ` #` after an unquoted value starts a comment |
| `.properties` keys | Matched on the logical (unescaped) key; values stay raw |
| Dependencies | None new. Handwritten line tokenizers |

## Conflicts with current requirements / code

1. **Config validation** (`internal/config/config.go` `Validate`) runs
   `format.ParsePath` on every `encrypt` entry. That rejects legal literal
   keys such as `a..b` or `foo[`, which contradicts REQUIREMENTS § Value
   selection. → AC-4.11.
2. **Format detection** (`format.For`) uses `filepath.Ext`. `.env.local`
   resolves to `.local` and is rejected. → AC-5.16.
3. **Type preservation** (REQUIREMENTS, AC-3.2) doesn't apply: these
   formats have no types, so it's always `str`. Clarified in REQUIREMENTS.
4. **`Span.Value` doc** says "quotes removed, escapes resolved". For line
   formats it is the raw literal, so the doc comment needs updating.
5. **Open spec decisions** AC-5.10 (quoting) and AC-5.13 (continuation)
   are now decided.
6. **Docs**: USER_INTERACTIONS said "not implemented yet" (updated).
7. **Glob depth (fixed afterwards)**: `*.env` in `.nebel.yaml` used to
   match only at the repository root (doublestar), while `.gitattributes`
   matches at any depth (audit 2026-09-29 §153). Rules now match the way
   `.gitattributes` does (spec 04 AC-4.2, AC-4.3).

## Steps (each step leaves `go test ./...` green; one commit per step)

1. **Format detection** — `internal/format/format.go`
   - Add `Detect(name string) (Kind, bool)` working on a base name
     (AC-5.16). `For` uses it; config can reuse it on a glob's last segment.
   - Tests: name table (`.env`, `.env.local`, `prod.env`, `.env.json`,
     `app.properties`, `env`, `x.envrc`).
2. **Config validation** — `internal/config/config.go`
   - `Validate` chooses its key check from `Detect(path.Base(r.Files))`
     (AC-4.11).
   - Tests: `a..b` loads for `*.properties`, `A B` is rejected for
     `*.env`, a dot-path still parses for `*.yaml`, an unknown glob still
     uses `ParsePath`.
3. **Shared line tokenizer** — `internal/format/lines.go`
   - Splits into logical lines with real byte offsets, `\r` excluded,
     BOM skipped, lone `\r` per format (AC-5.17, 5.18). Shared duplicate-key and multi-line
     bookkeeping (AC-5.19, 5.20). Errors `ErrDuplicateKey`,
     `ErrMultiline`, `ErrMalformed` with line numbers.
4. **`.env` handler** — `internal/format/env.go`
   - Grammar per spec 05 § `.env`: export, quotes, `\"`, inline comments,
     spaces around `=`, empty values, unterminated quotes (AC-5.9, 5.10,
     5.21–5.24, 5.26–5.29).
   - Tests: AC-5.1 byte-exactness over a fixture with every construct,
     plus LF and CRLF variants.
5. **`.properties` handler** — `internal/format/properties.go`
   - `=`/`:`/whitespace separators, `#`/`!` comments, continuation
     detection, logical-key unescaping incl. `\uXXXX`, trailing whitespace
     kept in values (AC-5.11–5.13, 5.30–5.32).
6. **Filter integration** — `internal/filterop/filterop.go`
   - Smudge context guard for line formats (AC-5.25, AC-6.15). Everything else
     should already work through the `Handler` interface. Update the
     `Span.Value` doc comment.
   - Tests: clean→smudge round trip (AC-6.5), idempotence (AC-6.3),
     per-field key versions (AC-6.13), and a new golden ciphertext for one
     `.env` and one `.properties` value in `golden_test.go` (AC-6.14).
7. **CLI** — `cmd/nebel`
   - `add field` e2e for both formats, incl. the picker and refusal of
     duplicate/multi-line keys (AC-8.12). `undecrypted.go` and rotate get
     the formats for free via `format.For`; add one rotate e2e on a `.env`
     to prove it.
8. **Docs** — README format table and examples, plus how rule patterns
   match.

## Upgrading

No migration. Before this feature `format.For` rejected `.env` and
`.properties`, so no repository can hold value-mode ciphertext for them
yet. The first release that ships it pins the span boundaries (see Risks).

## Risks

- **Span boundaries are permanent once shipped.** Committed ciphertext
  depends on exactly which bytes are the "raw literal". The golden tests
  in step 6 pin this; any later change to the boundaries is a breaking
  format change.
- **Dotenv dialects differ** (compose, godotenv, python-dotenv, Node).
  The grammar targets the common subset. Anything outside it fails
  closed (`ErrMalformed`) rather than being guessed at.
- **Tampering via line injection** is covered by SIV authentication plus
  the smudge context guard (AC-6.15).
- **Quote edits on the encrypted form** are authenticated for `.env`:
  the quote style is in the AAD (spec 06 AC-6.16), so re-quoting a tag
  (e.g. a linter run on committed blobs, or an edit in a clone without
  the key) makes checkout fail for that key until the quotes are
  restored. That's deliberate: the alternative is smudging `"a\nb"` back
  as `'a\nb'`, a silently different value. Linting the plaintext working
  tree is unaffected, since clean re-encrypts under the new quotes.
