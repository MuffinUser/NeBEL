# Spec 11 — Security Audit Report

**Datum:** 2026-09-25
**Objekt:** strucrypt Krypto-Implementierung (Go)
**Prüfungsart:** Statische Code-Analyse, kryptografische Design-Bewertung
**Modell:** qwen-3.6-35b-sovereign

---

## 1. Architektur-Überblick

```
Password ──► Argon2id ──► HKDF-Expand ──► AES-256-SIV (64 Byte Schlüssel)
                        Salt (16B, CSPRNG)    AAD: mode + filePath + fieldPath
```

| Komponente        | Implementierung                              |
|-------------------|---------------------------------------------|
| Schlüsselableitung| Argon2id + HKDF-Expand (SHA-256)            |
| Verschlüsselung   | AES-256-SIV (RFC 5297), Tink Crypto         |
| AAD-Bindung       | `binary.AppendUvarint`-kodiert              |
| Canary-Verifikation| AES-256-SIV über konstanten Plaintext      |
| Tag-Format        | `ENC[AES256_SIV,data:<base64>]`             |

---

## 2. Positive Befunde

### Kryptografische Grundwahl

- **Argon2id** (nicht Argon2i oder Argon2d) – korrekte Wahl gegen Side-Channel- und GPU-Angriffe.
- Parameter **t=3, m=64 MiB, p=4** entsprechen RFC 9106 Abschnitt 4, Option 2 („recommended" für general-use).
- Salz wird über **`crypto/rand`** generiert – ausreichend 16 Byte für Replay-Schutz.
- **AES-256-SIV** ist die richtige Wahl für deterministische Verschlüsselung (Git-Filter-Use-Case).
- Tink Crypto als implementierende Bibliothek – etabliert, auditiert, maintained.

### AAD-Design

- Längen-prefixierte Verkettung von `(mode, filePath, fieldPath)` über `binary.AppendUvarint` verhindert **Two-Part Collisions**.
- Keine zwei verschiedenen `(mode, filePath, fieldPath)`-Tripel können die gleichen AAD-Bytes produzieren.
- Ciphertext-Replay zwischen verschiedenen Feldern wird dadurch unmöglich.

### Fehlerbehandlung

- Auth-Failure (falscher Schlüssel, AAD-Mismatch, Tampering) → **`ErrAuth`**, niemals teilweise Plaintext-Ausgabe.
- Canary-Verification verhindert Registrierung des Filters mit falschem Schlüssel (**fail closed**).
- Idempotenz: bereits verschlüsselte Werte werden nicht double-encrypted.
- Leere Passwörter werden strikt abgelehnt.

### Passwort-Eingabe-Sicherheit

- **argv wird strikt abgelehnt** – dokumentiert begründet ( `/proc/<pid>/cmdline`, Shell-History, CI-Logs).
- Drei sichere Alternativen: `$STRUCRYPT_PASSWORD`, `--password-stdin`, interaktives `term.ReadPassword`.

### Tag-Format

- Base64-Standard-Alphabet (keine ` `, `,` oder `]`) → keine Trennzeichen-Kollision im Parser.
- Algorithm-Identifier in Tag überprüft – andere Algorithmen werden abgelehnt.

### Domain Separation

- HKDF-Info-String `"strucrypt v1 aes-256-siv key"` trennt die KDF-Pipeline von jeder anderen Verwendung.
- Canary verwendet eigenen AAD-String `"strucrypt-canary"`.
- ModeFile vs. ModeValue erzeugt verschiedene AAD-Bytes.

---

## 3. Bewertung: Mittel-Risiko

### M-1: Schlüssel im Klartext in `.git/config`

**Stelle:** `internal/localkey/localkey.go:1`–`37`

Der abgeleitete 64-Byte-Schlüssel wird als Base64 in `.git/config` gespeichert. Diese Datei hat standardmäßig `0644`-Permission – jeder Benutzer auf dem System mit Lesezugriff auf das Home-Verzeichnis kann den Schlüssel lesen.

**Begründete Akzeptanz:** Das ist die gleiche Vertrauensgrenze wie bei git-crypt und transcrypt. Der Schlüssel schützt Daten *lokal* gegen unautorisierten Commit; er ist nicht konzipiert zum Schutz gegen andere Nutzer auf demselben System. Das shared-secret-Modell ohne asymmetrische Verschlüsselung erfordert dieses Modell.

**Empfohlene Maßnahme:** Optional `.git/config` auf `0600` setzen oder `gpg-agent` / Keyring-Integration für Schlüssel-Speicherung nachreichen.

### M-2: Kein Schlüssel-Rotationsmechanismus

**Stelle:** Gesamtes System (keine Rotation-Logik vorhanden)

Es gibt keinen Mechanismus zur Schlüssel-Rotation. Bei Kompromittierung des gespeicherten Schlüssels sind **alle** verschlüsselten Daten sofort lesbar. Die Argon2id-Parameter sind hardcoded und tragen keine Versionsinformation – bestehende Repositories können nicht transparent migriert werden.

**Empfohlene Maßnahme:** Später: Rotations-Workflows implementieren (neuer Salt, alle Felder neu verschlüsseln, alter Config-Eintrag verwerfen). Versionsfeld in Config-Datei hinzufügen für zukünftige Parameter-Migration.

---

## 4. Bewertung: Niedrig-Risiko (Informational)

### L-1: Deterministische Verschlüsselung leakt Gleichheit

Zwei gleiche Geheimnisse am gleichen Ort (gleicher Dateipfad, gleiches Feld) produzieren identische Ciphertexts. Das ist **by design** – verhindert Git-Diffs bei re-encryption – bedeutet aber, dass ein Angreifer mit Ciphertext-Zugang erkennen kann, ob zwei Felder den gleichen Wert enthalten. Die AAD-Bindung verhindert nur Cross-Field-Replay, nicht die Gleichheits-Leakage selbst.

**Bewertung:** Akzeptabel für das gegebene Threat-Model. Git-integrierte Verschlüsselung ohne Re-Encryption pro Commit macht Random-Nonce-AEAD (GCM, CTR) unmöglich.

### L-2: Argon2id-Speicherverbrauch für langfristige Secrets

64 MiB sind für interaktive Nutzung (~100 ms auf Entwicklertop) angemessen. Für langfristige Secrets (mehrere Jahre Schutzbedarf) könnte OWASP „recommended" (128–256 MiB) sinnvoller sein.

**Bewertung:** Trade-off zwischen Usability und langfristiger Brute-Force-Resistenz. Nicht akut kritisch, aber dokumentiert.

### L-3: Single-Key-Modell

Ein Schlüssel deckt alle Dateien, alle Felder, alle Umgebungen ab. Key-Usage-Degradation bei SIV ist in der Praxis nicht relevant, bedeutet aber: **ein Kompromiss = Total-Compromise**.

**Bewertung:** Architektur-bedingt und bewusst. Bei Bedarf später: Multi-Key-Umgebung pro Branch/Environment.

### L-4: `.git/config`-Dateiberechtigung

Die `.git/config`-Datei wird nicht explizit auf eine restriktive Permission gesetzt. Standardmäßig erstellt Git mit 0644.

**Empfohlene Maßnahme:** `os.WriteFile` für `.git/config` mit `0600` ersetzen (betrifft `git config --local`).

### L-5: Plaintext-Passwort in Memory

Das Passwort wird als `string` (unveränderlich) im Speicher gehalten, bevor es zur Argon2id-Berechnung als `[]byte` kopiert wird. Go's Garbage Collector gibt den Speicher nicht sofort frei.

**Bewertung:** Minimalrisiko in dieser Anwendung. Das Passwort verweilt nur während der Init-Phase im Speicher. Für höhere Sicherheit: `golang.org/x/crypto/argon2`-CompatibleMemoryClear-Pattern oder `memguard`-Bibliothek.

---

## 5. Keine kritischen Schwachstellen gefunden

Kritische Schwachstellen im Sinne von:

- Verwendetem gebrochenem/altem Cipher (DES, RC4, ECB-Mode)
- Schwachem RNG (z. B. `math/rand` statt `crypto/rand`)
- Fehlender Authentisierung (AES ohne MAC/GCM ohne Tag)
- Timing-Angriffsanfälligkeit auf Geheimnissen
- Unsachgemäßer Salt-Generierung (z. B. aus `time.Now()`)

… wurden **nicht identifiziert**.

---

## 6. Abgleich mit Specs (AC-Mapping)

| Spec | AC | Implementierung | Status |
|------|----|----------------|--------|
| 01 | AC-1.1 Deterministisch | `kdf.Derive()` | ✅ |
| 01 | AC-1.2 Salt-Sensitivity | `kdf.Derive()` | ✅ |
| 01 | AC-1.3 Password-Sensitivity | `kdf.Derive()` | ✅ |
| 01 | AC-1.4 Fixed Parameters | `kdf.go:39-43` | ✅ |
| 01 | AC-1.5 Correct Size (64 B) | `kdf.go:18`, HKDF | ✅ |
| 01 | AC-1.6 Fresh Salt | `kdf.NewSalt()` + `crypto/rand` | ✅ |
| 01 | AC-1.7 Reject Bad Input | `kdf.Derive()` validation | ✅ |
| 01 | AC-1.8 Golden Vector | `kdf_test.go:138-149` | ✅ |
| 02 | AC-2.1 AES-256-SIV (RFC 5297) | `siv.go` via Tink | ✅ |
| 02 | AC-2.2 AAD binding | `siv.AAD()` Uvarint-kodiert | ✅ |
| 03 | AC-3.1 Tag format | `tag.EncodeValue()` | ✅ |
| 03 | AC-3.2 Type preservation | `tag.Type` + `tag.Render()` | ✅ |
| 04 | AC-4.8 Canary constant | `canary.go:13-16` | ✅ |
| 05 | AC-5.1 Verbatim outside edits | `format.Splice()` | ✅ |
| 05 | AC-5.2 Error on missing field | `filterop.cleanValues()` | ✅ |
| 06 | AC-6.4 Skip re-encrypt | `filterop.Clean()` | ✅ |
| 06 | AC-6.6 No-key passthrough | `localkey.Get()` ok=false | ✅ |
| 06 | AC-6.7 Untagged passthrough | `filterop.Smudge()` | ✅ |
| 06 | AC-6.9 Fail on corrupt | `filterop.Smudge()` error | ✅ |
| 07 | AC-7.4 Self-consistent config | `cfg.VerifyCanary(key)` | ✅ |
| 07 | AC-7.7 Wrong password: no filter | `joinRepo()` before register | ✅ |
| 07 | AC-7.8 Re-checkout after join | `gitutil.CheckoutAll()` | ✅ |
| 07 | AC-7.2 Generate password | `generatePassword()` | ✅ |

---

## 7. Fazit

Die kryptografische Implementierung von strucrypt ist **solide und durchdacht**. Alle grundlegenden kryptografischen Primitive sind korrekt gewählt und implementiert. Das Design berücksichtigt die besonderen Anforderungen des Git-Filter-Treibers (Determinismus für diff-stabile Chiffres) ohne dabei fundamentale Sicherheitsgarantien zu opfern.

Das shared-secret-Modell erfordert akzeptierte Vertrauensgrenzen (Schlüssel im Klartext lokal, Single-Key-Architektur), die transparent dokumentiert und mit anderen Tools in diesem Raum (git-crypt, transcrypt) gleichgesetzt sind.

**Gesamtbewertung: ✅ Bestanden.** Keine kritischen oder hohen Schwachstellen identifiziert. Zwei Medium-Risiko-Befunde sind architekturbedingt und nicht akut.

---

## Signatur

```
─────────────────────────────────────────────────────
 Geprüft von: qwen-3.6-35b-sovereign

 Datum:       2026-09-25
─────────────────────────────────────────────────────
```
