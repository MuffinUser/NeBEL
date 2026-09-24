# Spec 02 — Encryption primitive (AES-256-SIV)

Wraps a vetted AES-SIV implementation with the path/context-bound AAD
scheme. See REQUIREMENTS.md § Encryption.

## Acceptance criteria

- **AC-2.1 Deterministic**: encrypting the same `(key, plaintext, aad)`
  twice produces byte-identical ciphertext.
- **AC-2.2 AAD binding**: the same `(key, plaintext)` with two different
  `aad` values (e.g. different file/field path) produces different
  ciphertext.
- **AC-2.3 AAD authentication**: ciphertext produced with `aad = X` fails
  to decrypt (returns an explicit error) when given `aad = Y`.
- **AC-2.4 Round-trip**: `decrypt(encrypt(pt, key, aad), key, aad) == pt`
  for: empty input, short strings, multi-KB blobs, and inputs containing
  arbitrary/binary bytes.
- **AC-2.5 Wrong key rejected**: decrypting with an incorrect key returns
  an explicit authentication error, never a wrong-but-plausible plaintext.
- **AC-2.6 Tamper detection**: flipping any single bit in stored
  ciphertext causes decryption to fail authentication.
- **AC-2.7 Key size enforced**: the primitive rejects a key that isn't the
  512 bits produced by spec 01, with a clear error (fail fast on
  misconfiguration rather than undefined behavior).
