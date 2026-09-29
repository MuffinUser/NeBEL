# Spec 05 — Format handlers (YAML, JSON, .env, .properties)

Locate a value by path/key and replace it in place, preserving everything
else in the file byte-for-byte. See REQUIREMENTS.md § Value selection,
§ Supported file formats.

Handlers do not re-serialize. Each locates the target scalar's byte span
and the caller splices a replacement into the original bytes — the only
way to satisfy AC-5.1, since round-tripping a document through a YAML
marshaller already collapses `host: db.internal   # comment` to a single
space, and would produce git diffs on lines nobody edited.

## Shared acceptance criteria (all formats)

- **AC-5.1 Byte-exact preservation**: after replacing a target value with
  an `ENC[...]` tag (or reverse), every byte of the file outside the
  changed value(s) is identical to the original — comments, key order,
  indentation, blank lines, unrelated values.
- **AC-5.2 Missing path errors**: a configured path/key that doesn't exist
  in a given file produces a clear error at clean/add time, not a silent
  no-op.
- **AC-5.3 Multiple targets in one file**: a file with several configured
  paths encrypts/decrypts all of them in a single pass, independently.

## YAML

- **AC-5.4**: a dot-path (`database.password`) resolves to the correct
  scalar node in nested mappings.
- **AC-5.5**: a path with an array index (`api.keys[0]`) resolves to the
  correct sequence element.
- **AC-5.6**: the style of scalars the rule does not name is preserved
  exactly, because the file is never re-serialized: a handler locates the
  target scalar's byte span and the caller splices over it, copying every
  other byte through untouched.

  Known limitation, for the encrypted scalar itself: a string is emitted
  double-quoted whatever style it was written in, since the tag records
  the value's type but not its style. Double quotes are the one style
  safe in both block and flow context — an `ENC[...]` tag contains `[`,
  `]` and `,`, and would otherwise terminate a flow sequence early. The
  ciphertext derives from the value, not the styling, so a re-quoted
  scalar still cleans to an identical blob: git shows no diff, and the
  drift is confined to the working tree, once.
- **AC-5.14 Control characters are escaped, not spliced in raw**: a
  decrypted string containing a control character (newline, tab, ...) is
  rendered with an explicit escape sequence, not the literal byte. A raw
  control character spliced directly into a double-quoted scalar is not
  a syntax error, but is silently reinterpreted by YAML's own
  line-folding rules on the next parse — e.g. a literal newline becomes a
  plain space — changing the logical value on a later decrypt/encrypt
  round trip with no error ever raised (2026-09-29 audit, P10). `\n`,
  `\r`, `\t`, `\0`, `\a`, `\b`, `\v`, `\f`, and `\e` (YAML's own
  single-character escapes) are supported. A control character with no
  such escape is refused outright with a clear error rather than
  attempted via a `\xHH`/`\uHHHH` hex escape: the `goccy/go-yaml` parser
  this codebase depends on has a confirmed bug mistracking a scalar
  token's source span for any hex escape, which would silently corrupt a
  later `Locate` of that same field instead of failing where the problem
  actually is.
- **AC-5.15 Multi-document YAML is rejected**: a source containing more
  than one `---`-separated document fails clearly rather than silently
  operating on only the first. Resolving a path across documents raises
  its own ambiguity (the same path present in two documents: which one
  does a single `encrypt` entry protect, and which does smudge restore
  into?) that this codebase does not attempt to resolve; a configured
  path matching a leaf only in a later document previously went
  undetected entirely — never encrypted, never even reported as missing
  (2026-09-29 audit, P11).

## JSON

- **AC-5.7**: a dot-path resolves to the correct nested field, including
  array indices, mirroring AC-5.4/5.5 for JSON structure.
- **AC-5.8**: key order and the whitespace/formatting of untouched parts
  of the document are preserved. Located with `encoding/json`'s streaming
  tokenizer, which reports byte offsets; no third-party dependency and no
  re-marshalling.

## `.env`

- **AC-5.9**: an exact key match (`DATABASE_PASSWORD`) replaces only that
  line's value; other lines are untouched byte-for-byte.
- **AC-5.10**: existing quoting conventions (`KEY="value"` vs `KEY=value`)
  are preserved or documented as normalized — pick one behavior and test
  it explicitly.

## `.properties`

- **AC-5.11**: an exact key match replaces only that entry's value; other
  entries untouched byte-for-byte.
- **AC-5.12**: both `=` and `:` key/value separators (valid in Java
  `.properties`) are supported.
- **AC-5.13**: line-continuation syntax (trailing `\`) is either supported
  correctly or explicitly rejected with a clear error — decide and test
  one behavior, don't leave it undefined.
