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


## Line-based formats (`.env`, `.properties`) — shared

`.env` and `.properties` have no nesting and no native scalar types, so
two rules from the structured formats change for them:

- **Addressing**: a configured path is the **literal key**, matched
  exactly. A dot or bracket in it is just a character
  (REQUIREMENTS.md § Value selection). `format.ParsePath` is never called
  for these formats.
- **What gets encrypted is the raw literal**: the value text exactly as
  written between its delimiters, with no unquoting and no unescaping.
  Quotes, if any, stay in the file *outside* the span. Smudge writes the
  literal back unchanged. This makes AC-6.5's exact reversal hold by
  construction and means there's never a re-render that could change
  meaning (e.g. single to double quotes turning on `$` interpolation in
  docker-compose). The trade-off is accepted: switching a value's quote
  style doesn't change its ciphertext, and the quote change shows up in
  git as an ordinary edit outside the tag. `Span.Value` holds the raw
  literal for these formats.
- **Type**: always `type:str`. Neither format has native types, so
  REQUIREMENTS.md § type preservation / spec 03 AC-3.2 has nothing to
  preserve here.

Both formats are parsed by small handwritten line tokenizers in
`internal/format`, with no new dependency. No maintained Go dotenv or
properties library reports byte offsets, and AC-5.1 needs offsets.

- **AC-5.14 Format detection by name**: `format.For` picks a handler
  from the file's *base name*, in this order:
  1. extension `.yaml`/`.yml` → YAML, `.json` → JSON, `.properties` →
     properties, `.env` → env;
  2. otherwise a base name equal to `.env` or starting with `.env.` →
     env (`.env`, `.env.local`, `.env.production`).

  A known extension wins over the `.env.` prefix, so `.env.json` is JSON.
  Anything else is `ErrUnsupportedFormat`. A table test lists matching and
  non-matching names.
- **AC-5.15 CRLF**: on a file with `\r\n` line endings, located spans and
  `Span.Value` never include the `\r`, and AC-5.1 holds with the CRs left
  in place. This is the line-format equivalent of the YAML CRLF fix in
  70d7d5f; a Windows checkout with `core.autocrlf=true` must round-trip.
  A file mixing `\n` and `\r\n` is handled line by line.
  A lone `\r` (not followed by `\n`) differs by format. In
  `.properties` it is a line terminator, as in `java.util.Properties`, so
  `a=1\rpassword=x` is two entries. In `.env` it is `ErrMalformed`. So a
  located raw literal can never contain `\r` or `\n`.
- **AC-5.16 BOM**: a leading UTF-8 BOM is not part of the first key, and
  it is preserved byte-for-byte.
- **AC-5.17 Duplicate configured key rejected**: if a configured key
  occurs more than once in the file, `Locate` fails with
  `ErrDuplicateKey`, naming the key and every line number it appears on.
  Both formats use the *last* occurrence at runtime, so encrypting any one
  occurrence could leave the effective value in plaintext. Duplicates of
  keys *not* configured are ignored.
- **AC-5.18 Multi-line values: tokenized, never located**: the tokenizer
  recognizes multi-line constructs (`.properties` continuation lines, a
  `.env` quoted value whose closing quote is on a later line). That way it
  never misreads a continuation line such as `  password=x` as a key of
  its own. `Locate` on a configured key whose value spans more than one
  line fails with `ErrMultiline`; the error suggests `mode: file` for
  values like PEM keys. This resolves AC-5.13. Support can be added later
  without a format break, because no such tag can exist yet.
- **AC-5.19 Malformed line rejected**: a line that is neither blank, a
  comment, nor a key/value entry fails `Locate` and `Leaves` with
  `ErrMalformed`, naming the line number. The handler fails closed rather
  than skipping text it doesn't understand, since that text might hide a
  key.
- **AC-5.20 Empty value**: `KEY=` (or `KEY=""`) locates a zero-length span
  at the value position and is encrypted like any other value. Leaving it
  unencrypted would reveal that the secret is blank.
- **AC-5.21 Render is verbatim**: `Render(value, t)` returns `value`
  unchanged for both formats, both for an `ENC[...]` tag on clean and
  for the raw literal on smudge. Quotes live outside the span, so there is
  nothing to add. An `ENC[...]` tag is safe as an unquoted value in both
  formats: it contains no whitespace, `#`, `!`, `$`, quote or backslash.
- **AC-5.22 Picker leaves**: `Leaves` returns every key/value entry in
  source order, with `Path` = literal key, `Value` = raw literal,
  `Type` = `str`. Entries with a duplicated key (AC-5.17) or a multi-line
  value (AC-5.18) are omitted, because selecting them could only fail.
- **AC-5.23 Smudge checks the literal against its current context**:
  quotes are outside the span and outside the AAD, so they can change
  after clean (hand edit, linter auto-fix) without failing
  authentication. Before splicing, smudge checks that the decrypted raw
  literal is valid where the tag *now* sits, and errors otherwise rather
  than writing a silently different value:
  - any line format: no `\n` or `\r` (clean can never produce one,
    AC-5.15/5.18; one could only come from a crafted tag and would inject
    new lines);
  - `.env` double-quoted: no unescaped `"`;
  - `.env` single-quoted: no `'`;
  - `.env` unquoted: doesn't start with a quote character, has no
    whitespace followed by `#`, and has no leading or trailing whitespace;
  - `.properties`: no leading whitespace, and doesn't end in an odd
    number of backslashes.

  The handler exposes the check (e.g. `CheckLiteral(src, span, literal)`),
  and `filterop` (spec 06) calls it.

## `.env`

Grammar, per line (leading and trailing whitespace around tokens is
preserved outside spans):

```
blank     := WS*
comment   := WS* "#" ANY*
entry     := WS* ["export" WS+] KEY WS* "=" WS* VALUE WS* [ "#" ANY* ]
KEY       := one or more chars, none of them whitespace or "="
VALUE     := unquoted | "'" ANY* "'" | '"' ( "\" ANY | not-'"' )* '"'
unquoted  := runs to end of line, stopping before WS+ "#"; trailing WS excluded
```

- **AC-5.9**: an exact key match (`DATABASE_PASSWORD`) replaces only that
  line's value; other lines are untouched byte-for-byte.
- **AC-5.10 Quoting preserved**: the quote style is preserved, never
  normalized. For `KEY=value`, `KEY='value'` and `KEY="value"` the span
  covers `value` only, so clean produces `KEY=ENC[...]`,
  `KEY='ENC[...]'` and `KEY="ENC[...]"` respectively. Inside double
  quotes, `\"` doesn't close the value and stays in the raw literal as is.
- **AC-5.24 `export` prefix**: `export KEY=value` is located by `KEY`,
  and `export ` is preserved outside the span.
- **AC-5.25 Inline comments**: for an unquoted value, whitespace followed
  by `#` starts a comment that is excluded from the span and preserved.
  A `#` not preceded by whitespace (`KEY=abc#def`) is part of the value.
  After a closing quote, only whitespace and an optional `# comment` may
  follow; anything else is `ErrMalformed`.
- **AC-5.26 Spaces around `=`**: `KEY = value` locates `value`, and the
  surrounding whitespace is preserved outside the span.
- **AC-5.27 Unterminated quote**: a quote that is never closed by end of
  file is `ErrMalformed`. One closed on a later line is the multi-line
  case (AC-5.18).

## `.properties`

Follows `java.util.Properties.load` line syntax, treated as bytes. The
raw-literal rule means ISO-8859-1 vs UTF-8 never matters, since nothing is
ever decoded.

- **AC-5.11**: an exact key match replaces only that entry's value; other
  entries are untouched byte-for-byte.
- **AC-5.12 Separators**: `key=value`, `key:value` and `key value`
  (whitespace separator) are all supported, with optional whitespace
  around `=`/`:`. The value span starts after the separator and any
  whitespace following it, and runs to end of line (excluding the line
  terminator). Trailing whitespace is *included*, because Java keeps it as
  part of the value.
- **AC-5.13 Line continuation**: a line ending in an odd number of
  backslashes continues onto the next line. The tokenizer joins such lines
  to find entry boundaries, and `Locate` on a key whose value continues
  is `ErrMultiline` (AC-5.18). Decided: rejected, not supported, in v1.
- **AC-5.28 Comments**: lines whose first non-whitespace character is `#`
  or `!` are comments.
- **AC-5.29 Key matching on the logical key**: a configured key is
  compared with the key as Java would read it, with `\ `, `\:`, `\=`,
  `\\`, `\t`/`\n`/… and `\uXXXX` escapes resolved. So `my\ key` is matched
  by the configured key `my key`. Duplicate detection (AC-5.17) uses the
  same logical key, so `ab` and `ab` count as the same key. Only the
  *value* is raw-literal; the key itself is never rewritten.
- **AC-5.30 Escapes in values stay raw**: `\uXXXX` and other escapes in a
  value are part of the encrypted raw literal and come back unchanged on
  smudge.
