# Spec 03 — Encrypted value encoding

The inline `ENC[ALGO,key:<version>,data:<base64>,type:<type>]` tag used
to mark and store an encrypted value in place. `key` records which
project key version (spec 04, spec 11) produced this ciphertext — see
REQUIREMENTS.md § Key rotation for why one project can have values under
several versions at once.

## Acceptance criteria

- **AC-3.1 Encode string**: encoding a string value under key version `V`
  produces `ENC[AES256_SIV,key:V,data:<base64>,type:str]`.
- **AC-3.2 Type round-trip**: encoding then decoding an `int`, `float`,
  and `bool` value returns the original Go/native type, not a string
  (e.g. `port: 5432` decodes back to the integer `5432`).
- **AC-3.3 Detection**: a classifier function correctly identifies any
  value whose raw string starts with `ENC[` as "already encrypted", and
  anything else as plaintext — used by the clean/smudge filter for
  idempotency (spec 06).
- **AC-3.4 Correct decode**: decoding a well-formed tag with the key
  matching its declared version returns the original value and type.
- **AC-3.5 Wrong key**: decoding with a key that doesn't match the tag's
  declared version returns an explicit error (delegates to spec 02's
  AC-2.5), not corrupted output.
- **AC-3.6 Malformed tag rejected**: a truncated tag, invalid base64
  inside `data`, a missing or non-numeric `key`, or an unrecognized
  `ALGO` identifier is rejected with a clear error, not a panic.
- **AC-3.7 Unambiguous parsing**: the base64 alphabet used for `data`
  cannot contain the tag's own delimiter characters (`,`, `]`), so the tag
  can always be parsed unambiguously regardless of ciphertext content.
  `key`'s value is decimal digits only, for the same reason.
- **AC-3.8 Forward compatibility**: the `ALGO` field is checked explicitly
  — a tag naming an algorithm the running binary doesn't support fails
  with a clear "unsupported algorithm" error rather than attempting to
  decode it anyway.
- **AC-3.9 Parsing is version-agnostic**: parsing/decoding a tag never
  needs to know which version is "current" — the tag names its own
  version explicitly, and the caller (spec 06) is responsible for finding
  the matching key in the local keyring.
