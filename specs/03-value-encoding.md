# Spec 03 — Encrypted value encoding

The inline `ENC[ALGO,data:<base64>,type:<type>]` tag used to mark and
store an encrypted value in place. See REQUIREMENTS.md § Encrypted value
encoding.

## Acceptance criteria

- **AC-3.1 Encode string**: encoding a string value produces
  `ENC[AES256_SIV,data:<base64>,type:str]`.
- **AC-3.2 Type round-trip**: encoding then decoding an `int`, `float`,
  and `bool` value returns the original Go/native type, not a string
  (e.g. `port: 5432` decodes back to the integer `5432`).
- **AC-3.3 Detection**: a classifier function correctly identifies any
  value whose raw string starts with `ENC[` as "already encrypted", and
  anything else as plaintext — used by the clean/smudge filter for
  idempotency (spec 06).
- **AC-3.4 Correct decode**: decoding a well-formed tag with the correct
  key returns the original value and original type.
- **AC-3.5 Wrong key**: decoding with an incorrect key returns an explicit
  error (delegates to spec 02's AC-2.5), not corrupted output.
- **AC-3.6 Malformed tag rejected**: a truncated tag, invalid base64
  inside `data`, or an unrecognized `ALGO` identifier is rejected with a
  clear error, not a panic.
- **AC-3.7 Unambiguous parsing**: the base64 alphabet used for `data`
  cannot contain the tag's own delimiter characters (`,`, `]`), so the tag
  can always be parsed unambiguously regardless of ciphertext content.
- **AC-3.8 Forward compatibility**: the `ALGO` field is checked explicitly
  — a tag naming an algorithm the running binary doesn't support fails
  with a clear "unsupported algorithm" error rather than attempting to
  decode it anyway.
