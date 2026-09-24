# Spec 01 — Key derivation

Derives the 512-bit AES-256-SIV key material from a human password and a
stored (non-secret) salt. See REQUIREMENTS.md § Key management.

## Acceptance criteria

- **AC-1.1 Deterministic**: given the same `(password, salt)`, deriving
  key material twice produces byte-identical output.
- **AC-1.2 Salt sensitivity**: given the same password with two different
  salts, derived key material differs.
- **AC-1.3 Password sensitivity**: given the same salt with two different
  passwords, derived key material differs.
- **AC-1.4 Fixed parameters**: Argon2id time/memory/parallelism costs are
  fixed constants in code (not user-configurable in v1); document the
  chosen values and the reasoning (target: interactive-use cost on a
  typical dev laptop, per OWASP/Argon2 guidance).
- **AC-1.5 Correct output size**: HKDF expansion of the Argon2id output
  yields exactly 64 bytes (512 bits) — the key size AES-SIV requires
  (two 256-bit subkeys internally, per RFC 5297).
- **AC-1.6 Salt generation**: a freshly generated salt (at bootstrap) is
  produced via a CSPRNG (`crypto/rand`), is at least 16 bytes, and is
  treated as non-secret (safe to store in the committed config).
- **AC-1.7 No panics on bad input**: an empty password is rejected with a
  clear error rather than silently deriving a weak key.
