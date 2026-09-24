# Spec 05 — Format handlers (YAML, JSON, .env, .properties)

Locate a value by path/key and replace it in place, preserving everything
else in the file byte-for-byte. See REQUIREMENTS.md § Value selection,
§ Supported file formats.

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
- **AC-5.6**: encrypting a scalar preserves its original YAML style
  (quoted/unquoted, block/flow) as much as the chosen library
  (`yaml.v3` Node API) allows — document any known limitation.

## JSON

- **AC-5.7**: a dot-path resolves to the correct nested field, including
  array indices, mirroring AC-5.4/5.5 for JSON structure.
- **AC-5.8**: in-place edit (`tidwall/sjson`) preserves key order and
  original whitespace/formatting of untouched parts of the document.

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
