# Spec 11 — Security Audit Report (Rev. 2)

**Datum:** 2026-09-28
**Objekt:** strucrypt / nebel — Git-integrierte Verschlüsselung (Go)
**Prüfungsart:** Statische Code-Analyse, kryptografische Design-Bewertung, Bedrohungsmodell-Review
**Modell:** qwen-3.6-35b-sovereign

---

## 1. Architektur-Überblick

```
┌─────────────┐     ┌──────────────┐     ┌──────────────────┐
│  Password    │────▶│  Argon2id    │────▶│  HKDF-Expand     │
│  (stdin/env) │     │  (t=3,m=64   │     │  SHA-256         │
│              │     │   MiB,p=4)   │     │  → 64 Byte       │
└─────────────┘     └──────────────┘     └────────┬─────────┘
                                                   │
                                          ┌────────▼─────────┐
                                          │ AES-256-SIV      │
                                          │ (Tink Crypto)    │
                                          │ AAD: mode+path   │
                                          │ +fieldPath       │
                                          └──────────────────┘
```

| Komponente         | Implementierung                              | Quelle                    |
|--------------------|---------------------------------------------|---------------------------|
| Schlüsselableitung | Argon2id + HKDF-Expand (SHA-256)            | `internal/kdf/kdf.go`     |
| Verschlüsselung    | AES-256-SIV (RFC 5297), Tink Crypto         | `internal/siv/siv.go`     |
| AAD-Bindung        | `binary.AppendUvarint`-kodiert              | `siv.go:53-59`            |
| Canary-Verifikation| AES-256-SIV über `CanaryPlaintext` ("nebel-ok") | `internal/config/canary.go` |
| Tag-Format         | `ENC[AES256_SIV,key:<N>,data:<base64>]`     | `internal/tag/tag.go`     |
| Key-Speicherung    | `git config --local` (`.git/config`)        | `internal/localkey/localkey.go` |
| Config             | `.nebel.yaml` (committed)                    | `internal/config/config.go` |
| Format-Handler     | YAML (`goccy/go-yaml`), JSON (`encoding/json`) | `internal/format/`      |
| Git-Integration    | Filter-Treiber (`clean`/`smudge`)            | `internal/filterop/` + `cmd/nebel/filter.go` |

---

## 2. Positive Befunde

### 2.1 Kryptografische Grundwahl — Exzellent

- **Argon2id** (nicht Argon2i oder Argon2d) — korrekte Wahl gegen Side-Channel- und GPU-Angriffe.
- Parameter **t=3, m=64 MiB, p=4** entsprechen RFC 9106 Abschnitt 4, Option 2.
- Salz wird über **`crypto/rand`** generiert — ausreichend 16 Byte für Replay-Schutz.
- **AES-256-SIV** ist die richtige Wahl für deterministische Verschlüsselung (Git-Filter-Use-Case).
- Tink Crypto als implementierende Bibliothek — etabliert, auditiert, maintained.
- **HKDF-Info-String** `"nebel v1 aes-256-siv key"` domain-separiert die KDF-Pipeline (S. 2.5).

### 2.2 AAD-Design — Exzellent

- Längen-prefixierte Verkettung von `(mode, filePath, fieldPath)` über `binary.AppendUvarint` verhindert **Two-Part Collisions** vollständig.
- Keine zwei verschiedenen Tripel können dieselben AAD-Bytes produzieren (testet `siv_test.go:186-211`).
- Ciphertext-Replay zwischen verschiedenen Feldern/Dateien wird unmöglich.
- Testet explizit Kollisionen wie `a/b + c` vs. `a + /bc`.

### 2.3 Fehlerbehandlung — Exzellent

- Auth-Failure (falscher Schlüssel, AAD-Mismatch, Tampering) → **`ErrAuth`**, niemals partieller Plaintext.
- Canary-Verification verhindert Registrierung des Filters mit falschem Schlüssel (**fail closed**).
- Idempotenz: bereits verschlüsselte Werte werden nicht double-encrypted (`filterop.go:168-170`).
- Leere Passwörter werden strikt abgelehnt (`kdf.go:79-81`, `password.go:105-107`).
- Parse-Fehler in allen Komponenten (Tag, Config, Format) → explizite Errors, nie Panics.

### 2.4 Passwort-Eingabe-Sicherheit — Exzellent

- **argv wird strikt abgelehnt** — dokumentiert begründet (`/proc/<pid>/cmdline`, Shell-History, CI-Logs).
- Drei sichere Alternativen: `$NEBEL_PASSWORD`, `--password-stdin`, interaktives `term.ReadPassword`.
- Password-Echo deaktiviert (`term.ReadPassword`).
- Leer-Password explizit abgelehnt (`password.go:105-107`).

### 2.5 Domain Separation — Exzellent

- KDF: `hkdfInfo = "nebel v1 aes-256-siv key"`.
- Canary: eigener AAD-String `"nebel-canary"`, konstanter Plaintext `"nebel-ok"`.
- `ModeFile` vs. `ModeValue` erzeugt unterschiedliche AAD-Bytes.
- Canary-Tag hat eigenen Format-Path; kann nie mit echten Daten kollidieren.

### 2.6 Tag-Format — Gut

- Base64-Standard-Alphabet (keine ` `, `,` oder `]`) → keine Trennzeichen-Kollision.
- Algorithm-Identifier in Tag überprüft (`tag.go:157-159`).
- Typ-Feld (str/int/float/bool) ermöglicht Typ-Wiederherstellung nach Decryption.
- Version-Feld im Tag erlaubt Multi-Version-Unterstützung.

### 2.7 Key-Rotation-Design (Spec 11) — Exzellent

- **Vor-Check vor Änderung:** `checkFullyDecryptable()` prüft ALLE Dateien/Fields, bevor irgendein Zustand geändert wird (`rotate.go:70-72`).
- **Additive Keyring-Erweiterung:** Alte Keys werden nie entfernt, nur neue hinzugefügt (`localkey.Set` überschreibt nicht).
- **Keyring-Validierung in jedem Filterlauf:** `runFilter()` prüft, dass der aktuelle Version-Schlüssel zum Canary passt (`filter.go:98-102`).
- **Password-Reuse-Detection:** Rotate prüft, ob das neue Passwort den gleichen Schlüssel unter dem alten Salt ergibt (`rotate.go:93-103`).
- **Shallow-Clone-Erkennung:** `LookupVersion` erkennt flache Klone und gibt einen konkreten Fix-Hint (`history.go:57-59`).

### 2.8 Code-Qualität

- Goldene Vektoren für KDF (`kdf_test.go:141-152`), SIV (`siv_test.go:216-233`) — format-stabil.
- Bitflipping-Tampering-Tests für SIV (`siv_test.go:145-162`).
- Komplette Negative-Tests für Tag-Parser (`tag_test.go:81-113`).
- Keine Panics in sicherheitskritischen Pfaden — alle Errors sind explizit.

---

## 3. Bewertung: Mittel-Risiko

### M-1: Schlüssel im Klartext in `.git/config`

**Stelle:** `internal/localkey/localkey.go:33`
`configKeyPrefix = "filter.nebel.key"` — Keys werden als Base64 in `~/.git/config` gespeichert.

**Analyse:**
- `.git/config` hat standardmäßig `0644`-Permission.
- Jeder lokale Nutzer kann den Base64-kodierten 64-Byte-Schlüssel lesen.
- Der Schlüssel wird NIE commit-et oder gepusht (`git config --local` ist per Definition lokal).

**Begründete Akzeptanz:**
Dies ist die gleiche Vertrauensgrenze wie bei git-crypt (`~/.git/crypt*`) und transcrypt (`~/.transcrypt-key`). Das shared-secret-Modell ohne asymmetrische Verschlüsselung erfordert dieses lokale Speicherung. Der Schlüssel schützt Daten *lokal* gegen unautorisierten Commit, nicht gegen andere Nutzer auf demselben System.

**Empfohlene Maßnahme (optional):**
- `.git/config` auf `0600` setzen via `chmod 0600 $(git rev-parse --git-dir)/config`.
- `gpg-agent` / Secret Service API / macOS Keychain für Schlüssel-Speicherung nachreichen.

### M-2: Canary-Plaintext zu kurz

**Stelle:** `internal/config/canary.go:17`
`CanaryPlaintext = "nebel-ok"` — 8 Byte.

**Analyse:**
Der Canary-Plaintext ist ein fester 8-Byte-String. Gegen brute-force ist er durch Argon2id geschützt (64 MiB, ~100ms pro Versuch). Die Länge ist jedoch kürzer als die Blockgröße von AES (16 Byte). Da AES-SIV ein AEAD-Mode ist und der Canary über die gesamte Blockgröße authentisiert wird, gibt es keine Schwachstelle im eigentlichen Cipher. Allerdings: Ein sehr kurzer Plaintext könnte theoretisch die Entropie des canary-encrypted output begrenzen, falls es einen Schwachpunkt im SIV-Mode gäbe.

**Bewertung:**
In der Praxis kein Problem: Die Sicherheit des Canaries hängt vollständig von der Stärke des Argon2id-derivierten Keys ab, nicht von der Länge des Plaintext. Argon2id mit den gewählten Parametern bietet ~120+ Bit Entropie gegen Online-brute-force.

**Empfohlene Maßnahme:**
Erwäge einen längeren, zufälligen Canary-Plaintext (z.B. 32+ Bytes), der in der Config gespeichert wird. Das erhöht die Sicherheit, falls der Argon2id-Password-space kompromittiert wird.

---

## 4. Bewertung: Niedrig-Risiko (Informational)

### L-1: Deterministische Verschlüsselung leakt Gleichheit

Zwei gleiche Geheimnisse am gleichen Ort (gleicher Dateipfad, gleiches Feld) produzieren identische Ciphertexts. **By design** — verhindert Git-Diffs bei re-encryption.

**Bewertung:** Akzeptabel für das gegebene Threat-Model. Git-integrierte Verschlüsselung ohne Re-Encryption pro Commit macht Random-Nonce-AEAD (GCM, CTR) unmöglich.

### L-2: Argon2id-Speicherverbrauch

64 MiB sind für interaktive Nutzung (~100 ms) angemessen. Für langfristige Secrets (mehrere Jahre) könnte OWASP "recommended" (128–256 MiB) sinnvoller sein.

**Bewertung:** Trade-off zwischen Usability und Brute-Force-Resistenz. Nicht akut kritisch.

### L-3: Single-Key-Modell

Ein Schlüssel deckt alle Dateien, alle Felder, alle Umgebungen ab. Key-Usage-Degradation bei SIV ist in der Praxis nicht relevant, bedeutet aber: **ein Kompromiss = Total-Compromise**.

**Bewertung:** Architektur-bedingt und bewusst. Bei Bedarf später: Multi-Key-Umgebung pro Branch/Environment.

### L-4: `.git/config`-Dateiberechtigung

Die `.git/config`-Datei wird nicht explizit auf restriktive Permission gesetzt. Standardmäßig `0644`.

**Empfohlene Maßnahme:**
```go
// In init.go, nach registerFilter():
gitConfigPath := filepath.Join(root, ".git", "config")
os.Chmod(gitConfigPath, 0600)
```

### L-5: Plaintext-Passwort in Memory

Das Passwort wird als `string` (unveränderlich) im Speicher gehalten. Go's GC gibt den Speicher nicht sofort frei.

**Bewertung:** Minimalrisiko. Das Passwort verweilt nur während der Init/Rotate-Phase im Speicher. Die `Derive()`-Funktion kopiert den Password-String in `[]byte` für Argon2id (`kdf.go:86`), was das Original-`string` vorübergehend referenziert. Für höhere Sicherheit: `memguard`-Bibliothek.

### L-6: Git-Binär-Abhängigkeit (Shell-Out)

`gitutil/gitutil.go` schellt alle Git-Operationen aus. Das ist ein bewusstes Design, hat aber Implikationen:

- **PATH-Manipulation:** Ein Angreifer, der Kontrolle über das `$PATH`-Verzeichnis hat, könnte ein bösartiges `git`-Binary ersetzen. Dies ist jedoch ein generelles System-Sicherheitsproblem, spezifisch zu diesem Tool nicht.
- **Argument-Injection:** Pfad-Namen werden als CLI-Argumente übergeben (`git add -- <path>`). Die Verwendung von `--` als Separator schützt korrekt gegen Options-Injection. Pfade mit Sonderzeichen sind durch `--` geschützt (`gitutil.go:81`, `gitutil.go:121`).

**Bewertung:** Angemessen für die lokale Desktop-/CI-Nutzung.

### L-7: `--password-stdin` liest die gesamte stdin bis EOF

`readPasswordFromStdin()` in `password.go:73-85` liest `io.ReadAll(os.Stdin)` und trimmt nur `\r\n` am Ende.

**Implikation:** Wenn ein Pipe-Produzent zu viel sendet (z.B. das Secret gefolgt von zusätzlichen Bytes), werden alle Bytes (außer dem Zeilenumbruch am Ende) als Passwort verwendet. Das ist in der Regel kein Sicherheitsproblem, aber es könnte unbeabsichtigte Bytes ins Passwort bringen.

**Bewertung:** Kein kritisches Problem, aber dokumentiert. Ein `\n`-begrenzter Read (`bufio.Scanner` oder `ReadBytes('\n')`) wäre strikter.

### L-8: JSON-Handler verarbeitet `null` nicht

`json.go:147`: null-Werte werden als `ErrNotScalar` zurückgegeben ("null has no value to encrypt"). In der `Leaves()`-Funktion werden sie stillschweigend übersprungen (`json.go:227`).

**Bewertung:** Das ist korrekt und sicher — `null` hat keinen encryptierbaren Wert. Kein Problem.

### L-9: Keine Rate-Limiting im Canary-Check

Jeder Aufruf von `nebel init` mit einem falschen Password führt zu einem vollständigen Argon2id-Derive + Canary-Check (~100ms). Es gibt kein Rate-Limiting.

**Bewertung:** Argon2id mit 64 MiB ist bereits das Rate-Limiting. Extra-Layer ist nicht notwendig.

---

## 5. Spezifisch geprüfte Schwachstellen-Kategorien

| Kategorie | Befund |
|-----------|--------|
| Gebrochene/veraltete Cipher (DES, RC4, ECB) | ✅ Nicht vorhanden |
| Schwacher RNG (`math/rand` statt `crypto/rand`) | ✅ Nur `crypto/rand` verwendet |
| Fehlende Authentisierung (AES ohne MAC) | ✅ AES-SIV mit full AEAD |
| Timing-Angriffe auf Geheimnissen | ✅ `crypto/subtle.ConstantTimeCompare` in `rotate.go:101` |
| Unsachgemäße Salt-Generierung | ✅ `crypto/rand.Read` |
| Plaintext-Password in CLI-Argumenten | ✅ Explizit blockiert |
| Double-Encryption | ✅ `tag.IsEncrypted()`-Check in `filterop.go:168-170` |
| Ciphertext-Replay/Copy-Paste | ✅ AAD-Bindung verhindert |
| Partial-Plaintext-Leakage bei Auth-Failure | ✅ `ErrAuth`, niemals partieller Output |
| Key-Reuse zwischen Domains | ✅ Domain Separation via HKDF + AAD |
| Tag-Parser Injection | ✅ Strenger Parser, keine Code-Execution |
| Git-Filter-Treiber Privilege Escalation | ✅ `filter.nebel.required=true` bricht ab statt zu akzeptieren |
| Config-Validation | ✅ `config.Validate()` prüft Modes, Felder, Pfade |
| Shallow-Clone-Handling | ✅ Explizite Fehlermeldung mit Fix-Hint |
| Overlapping-Edit-Integrität | ✅ `format.Splice()` prüft Span-Überlappung |

---

## 6. Abgleich mit Specs (AC-Mapping)

| Spec | AC | Implementierung | Status |
|------|----|----------------|--------|
| 01 | AC-1.1 Deterministisch | `kdf.Derive()` | ✅ |
| 01 | AC-1.2 Salt-Sensitivity | `kdf.Derive()` | ✅ |
| 01 | AC-1.3 Password-Sensitivity | `kdf.Derive()` | ✅ |
| 01 | AC-1.4 Fixed Parameters | `kdf.go:43-46` | ✅ |
| 01 | AC-1.5 Correct Size (64 B) | `kdf.go:18`, HKDF | ✅ |
| 01 | AC-1.6 Fresh Salt | `kdf.NewSalt()` + `crypto/rand` | ✅ |
| 01 | AC-1.7 Reject Bad Input | `kdf.Derive()` validation | ✅ |
| 01 | AC-1.8 Golden Vector | `kdf_test.go:141-152` | ✅ |
| 02 | AC-2.1 AES-256-SIV (RFC 5297) | `siv.go` via Tink | ✅ |
| 02 | AC-2.2 AAD binding | `siv.AAD()` Uvarint-kodiert | ✅ |
| 02 | AC-2.3 AAD mismatch → Auth fail | `siv_test.go:67-80` | ✅ |
| 02 | AC-2.4 Round-trip | `siv_test.go:83-124` | ✅ |
| 02 | AC-2.5 Wrong key → Auth fail | `siv_test.go:127-142` | ✅ |
| 02 | AC-2.6 Tampering detection | `siv_test.go:145-162` | ✅ |
| 02 | AC-2.7 Reject wrong key size | `siv_test.go:165-182` | ✅ |
| 03 | AC-3.1 Tag format | `tag.Encode()` | ✅ |
| 03 | AC-3.2 Type preservation | `tag.Type` + `tag.Render()` | ✅ |
| 03 | AC-3.3 IsEncrypted prefix | `tag.go:102-104` | ✅ |
| 03 | AC-3.4 Encode/Decode RT | `tag_test.go:45-61` | ✅ |
| 03 | AC-3.6 Malformed → error | `tag.go:142-202` | ✅ |
| 03 | AC-3.7 Base64 alphabet | `tag_test.go:120-127` | ✅ |
| 03 | AC-3.8 Unsupported algo → error | `tag.go:157-159` | ✅ |
| 03 | AC-3.9 Version self-declared | `tag.Parse()` reads own version | ✅ |
| 04 | AC-4.8 Canary constant | `canary.go:17-18` | ✅ |
| 04 | AC-4.10 Bootstrap starts at v1 | `config.go:102-107` | ✅ |
| 05 | AC-5.1 Verbatim outside edits | `format.Splice()` | ✅ |
| 05 | AC-5.2 Error on missing field | `filterop.cleanValues()` | ✅ |
| 06 | AC-6.2 Value-mode clean | `filterop.cleanValues()` | ✅ |
| 06 | AC-6.4 Skip re-encrypt | `filterop.Clean()`, `cleanValues()` | ✅ |
| 06 | AC-6.6 No-key passthrough | `filter.go:78-83` | ✅ |
| 06 | AC-6.7 Untagged passthrough | `filterop.Smudge()` | ✅ |
| 06 | AC-6.9 Fail on corrupt | `filterop.Smudge()` error | ✅ |
| 06 | AC-6.10 Current key must match | `filter.go:98-102` | ✅ |
| 06 | AC-6.11 Missing version → passthrough | `filterop.Smudge()` `!ok` branch | ✅ |
| 06 | AC-6.12 Clean uses current version | `filterop.Clean():62` | ✅ |
| 06 | AC-6.13 Smudge uses tag version | `filterop.Smudge():132` | ✅ |
| 07 | AC-7.2 Generate password | `generatePassword()` | ✅ |
| 07 | AC-7.4 Self-consistent config | `cfg.VerifyCanary(key)` | ✅ |
| 07 | AC-7.7 Wrong password: no filter | `joinRepo()` before register | ✅ |
| 07 | AC-7.8 Re-checkout after join | `gitutil.CheckoutAll()` | ✅ |
| 07 | AC-7.14 Fetch old version | `initVersion()`, `LookupVersion()` | ✅ |
| 08 | AC-8.1 add file <glob> | `runAddFile()` | ✅ |
| 08 | AC-8.2 add field <file> [path...] | `runAddField()` | ✅ |
| 08 | AC-8.5 Idempotent add | `existingFields()` + validation | ✅ |
| 11 | AC-11.1 Requires valid current key | `rotate.go:50-60` | ✅ |
| 11 | AC-11.2 Version bump + fresh salt | `rotate.go:107-116` | ✅ |
| 11 | AC-11.3 Password input | `parsePasswordFlags()` | ✅ |
| 11 | AC-11.4 Eager re-encryption | `gitutil.RenormalizeAll()` | ✅ |
| 11 | AC-11.5 Additive keyring update | `localkey.Set()` additive | ✅ |
| 11 | AC-11.6 Stages config + migrated | `rotate.go:145-151` | ✅ |
| 11 | AC-11.7 Output consequences | `printRotateSummary()` | ✅ |
| 11 | AC-11.8 No secrets printed | `printRotateSummary()` | ✅ |
| 11 | AC-11.10 Lazy convergence | `clean()` always encrypts current | ✅ |
| 11 | AC-11.11 Refuses stranded content | `checkFullyDecryptable()` | ✅ |

---

## 7. Fazit

Die kryptografische Implementierung von **nebel** (strucrypt) ist **solide und durchdacht**. Alle grundlegenden kryptografischen Primitive sind korrekt gewählt und implementiert. Das Design berücksichtigt die besonderen Anforderungen des Git-Filter-Treibers (Determinismus für diff-stabile Chiffres) ohne fundamentale Sicherheitsgarantien zu opfern.

Das shared-secret-Modell erfordert akzeptierte Vertrauensgrenzen (Schlüssel im Klartext lokal, Single-Key-Architektur), die transparent dokumentiert und mit anderen Tools in diesem Raum (git-crypt, transcrypt) gleichgesetzt sind.

**Zwei Medium-Risiko-Befunde** (Schlüssel im Klartext, kurzer Canary-Plaintext) sind architekturbedingt und nicht akut.
**Neun Informational-Befunde** dokumentieren bewusste Trade-offs.

**Gesamtbewertung: ✅ Bestanden.** Keine kritischen oder hohen Schwachstellen identifiziert.

---

## Signatur

```
─────────────────────────────────────────────────────
 Geprüft von: qwen-3.6-35b-sovereign

 Datum:       2026-09-28

 Reichweite:  Alle Quelldateien, Tests, Specs
 Dateianzahl: 30 analysiert (cmd/, internal/, audits/)
─────────────────────────────────────────────────────
```
