// Copyright (C) 2026 Marwin Moellers
// SPDX-License-Identifier: GPL-3.0-or-later

package filterop

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/MuffinUser/nebel/internal/config"
	"github.com/MuffinUser/nebel/internal/format"
	"github.com/MuffinUser/nebel/internal/siv"
	"github.com/MuffinUser/nebel/internal/tag"
)

const valueDoc = `# Staging configuration.
database:
  host: db.internal      # not a secret
  password: "s3cr3t"
  port: 5432

api:
  token: alpha
`

func valueConfig(fields ...string) *config.Config {
	if len(fields) == 0 {
		fields = []string{"database.password"}
	}
	return &config.Config{Rules: []config.Rule{
		{Files: "config/*.yaml", Mode: config.ModeValue, Encrypt: fields},
	}}
}

// AC-6.2: clean on a mode: value rule encrypts only the configured
// scalars, leaving the rest of the document readable.
func TestCleanValuesEncryptsOnlyConfiguredFields(t *testing.T) {
	got, err := Clean(valueConfig(), testKeyring, "config/staging.yaml", []byte(valueDoc))
	if err != nil {
		t.Fatalf("Clean: %v", err)
	}

	if strings.Contains(string(got), "s3cr3t") {
		t.Errorf("the secret survived clean:\n%s", got)
	}
	for _, kept := range []string{"# Staging configuration.", "host: db.internal      # not a secret", "port: 5432", "token: alpha"} {
		if !strings.Contains(string(got), kept) {
			t.Errorf("clean disturbed content it should not touch (%q):\n%s", kept, got)
		}
	}
	if !strings.Contains(string(got), `password: "ENC[AES256_SIV_TB,`) {
		t.Errorf("encrypted field is not a quoted, type-bound ENC[...] tag:\n%s", got)
	}
}

// audit 2026-09-29, P08 (value-mode counterpart of
// TestCleanEncryptsPlaintextStartingWithEncPrefix): a configured field
// whose plaintext value merely starts with "ENC[" must still get
// encrypted, not be mistaken for an already-encrypted field and left as
// committed plaintext.
func TestCleanValuesEncryptsFieldStartingWithEncPrefix(t *testing.T) {
	doc := "password: \"ENC[mein-geheimnis, not actually a tag\"\n"
	got, err := Clean(valueConfig("password"), testKeyring, "config/staging.yaml", []byte(doc))
	if err != nil {
		t.Fatalf("Clean: %v", err)
	}
	if strings.Contains(string(got), "mein-geheimnis") {
		t.Errorf("plaintext field value starting with \"ENC[\" survived clean:\n%s", got)
	}
}

// AC-6.5 / AC-5.1 for per-value mode: everything the rule does not name
// survives a clean/smudge round trip byte for byte — comments, spacing,
// key order, and unrelated values.
func TestValueRoundTripLeavesUntouchedBytesExact(t *testing.T) {
	cfg := valueConfig("database.password", "database.port")

	cleaned, err := Clean(cfg, testKeyring, "config/staging.yaml", []byte(valueDoc))
	if err != nil {
		t.Fatalf("Clean: %v", err)
	}
	smudged, _, err := Smudge(cfg, testKeyring, "config/staging.yaml", cleaned)
	if err != nil {
		t.Fatalf("Smudge: %v", err)
	}
	if string(smudged) != valueDoc {
		t.Errorf("round trip changed the file:\n got  = %q\n want = %q", smudged, valueDoc)
	}
}

// audit 2026-09-29, P10, end-to-end: a field value containing a real
// newline (not the two-character escape) must survive a full Clean then
// Smudge cycle unchanged, through the actual encrypted tag — not just
// Render in isolation.
func TestValueRoundTripPreservesEmbeddedNewline(t *testing.T) {
	cfg := valueConfig("database.password")
	doc := "database:\n  password: \"line one\\nline two\"\n"

	cleaned, err := Clean(cfg, testKeyring, "config/staging.yaml", []byte(doc))
	if err != nil {
		t.Fatalf("Clean: %v", err)
	}
	smudged, _, err := Smudge(cfg, testKeyring, "config/staging.yaml", cleaned)
	if err != nil {
		t.Fatalf("Smudge: %v", err)
	}
	if string(smudged) != doc {
		t.Errorf("round trip changed the file:\n got  = %q\n want = %q", smudged, doc)
	}
}

// A field whose plaintext already contains a control character YAML
// cannot safely re-render (format.ErrControlCharacterUnsupported — see
// yamlEscapeDoubleQuoted's doc comment for why a hex-escape fallback isn't
// safe here) still cleans and encrypts without trouble — Clean never
// renders the plaintext itself, only the resulting ENC[...] tag, which is
// always plain ASCII. The failure surfaces on Smudge instead, where the
// decrypted plaintext would actually need writing back into the
// document, and it fails loudly rather than producing output a later
// Locate could silently corrupt on.
// audit 2026-09-30, R06: Clean used to accept and encrypt a value smudge
// could never render back out, discovering the failure only on the later,
// already-committed read-back path. Clean must refuse it up front instead.
func TestCleanValuesRejectsUnrenderableControlCharacter(t *testing.T) {
	cfg := valueConfig("database.password")
	doc := "database:\n  password: \"a\x01b\"\n"

	_, err := Clean(cfg, testKeyring, "config/staging.yaml", []byte(doc))
	if !errors.Is(err, format.ErrControlCharacterUnsupported) {
		t.Fatalf("Clean error = %v, want %v", err, format.ErrControlCharacterUnsupported)
	}
}

// audit 2026-09-30, R06: a JSON integer outside signed 64-bit range used to
// clean successfully (json.Number carries it as text, untyped-checked) and
// only fail on the later, already-committed smudge. Clean must refuse it
// up front instead.
func TestCleanValuesRejectsInt64Overflow(t *testing.T) {
	cfg := &config.Config{Rules: []config.Rule{
		{Files: "config/*.json", Mode: config.ModeValue, Encrypt: []string{"secret"}},
	}}
	doc := `{"secret": 18446744073709551615}`

	_, err := Clean(cfg, testKeyring, "config/staging.json", []byte(doc))
	if !errors.Is(err, ErrInvalidTypeLiteral) {
		t.Fatalf("Clean error = %v, want %v", err, ErrInvalidTypeLiteral)
	}
}

// Known limitation (spec 05 AC-5.6): a string written as a plain scalar
// comes back double-quoted, because the tag records the value's type but
// not the style it was written in. The ciphertext is derived from the
// value, so the re-quoted scalar still cleans to an identical blob and
// git shows no diff — the drift is confined to the working tree, once.
func TestValueRoundTripNormalizesPlainStringQuoting(t *testing.T) {
	cfg := valueConfig("api.token")

	cleaned, err := Clean(cfg, testKeyring, "config/staging.yaml", []byte(valueDoc))
	if err != nil {
		t.Fatalf("Clean: %v", err)
	}
	smudged, _, err := Smudge(cfg, testKeyring, "config/staging.yaml", cleaned)
	if err != nil {
		t.Fatalf("Smudge: %v", err)
	}
	if !strings.Contains(string(smudged), `token: "alpha"`) {
		t.Errorf("plain string was not normalized to double-quoted:\n%s", smudged)
	}

	// The drift must not compound: cleaning the re-quoted document has to
	// reproduce the same blob, or every checkout would dirty the file.
	recleaned, err := Clean(cfg, testKeyring, "config/staging.yaml", smudged)
	if err != nil {
		t.Fatalf("re-clean: %v", err)
	}
	if !bytes.Equal(recleaned, cleaned) {
		t.Errorf("re-cleaning the restored file changed the blob:\n got  = %s\n want = %s", recleaned, cleaned)
	}
}

// AC-3.2: a non-string scalar comes back as its original type, so
// `port: 5432` stays an integer rather than becoming the string "5432".
func TestValueRoundTripPreservesType(t *testing.T) {
	cfg := valueConfig("database.port")

	cleaned, err := Clean(cfg, testKeyring, "config/staging.yaml", []byte(valueDoc))
	if err != nil {
		t.Fatalf("Clean: %v", err)
	}
	if !strings.Contains(string(cleaned), "type:int") {
		t.Errorf("the integer's type was not recorded in the tag:\n%s", cleaned)
	}
	smudged, _, err := Smudge(cfg, testKeyring, "config/staging.yaml", cleaned)
	if err != nil {
		t.Fatalf("Smudge: %v", err)
	}
	if !strings.Contains(string(smudged), "port: 5432") {
		t.Errorf("integer was not restored unquoted:\n%s", smudged)
	}
}

// AC-6.3: clean is deterministic, so re-staging an unchanged file produces
// no diff.
func TestCleanValuesIsDeterministic(t *testing.T) {
	first, err := Clean(valueConfig(), testKeyring, "config/staging.yaml", []byte(valueDoc))
	if err != nil {
		t.Fatalf("first clean: %v", err)
	}
	second, err := Clean(valueConfig(), testKeyring, "config/staging.yaml", []byte(valueDoc))
	if err != nil {
		t.Fatalf("second clean: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Error("clean output differs between runs")
	}
}

// The CRLF regression (internal/format's yaml.go): a mode: value document
// using CRLF line endings throughout — the state a Windows clone's
// working tree is actually in, once core.autocrlf reintroduces "\r" that
// clean never put there — round-trips through Clean/Smudge byte-exact,
// same as the LF version, instead of Locate miscounting into the wrong
// part of the file.
func TestCleanValuesCRLFRoundTrips(t *testing.T) {
	crlf := strings.ReplaceAll(valueDoc, "\n", "\r\n")
	cfg := valueConfig("database.password")

	cleaned, err := Clean(cfg, testKeyring, "config/staging.yaml", []byte(crlf))
	if err != nil {
		t.Fatalf("Clean: %v", err)
	}
	smudged, _, err := Smudge(cfg, testKeyring, "config/staging.yaml", cleaned)
	if err != nil {
		t.Fatalf("Smudge: %v", err)
	}
	if string(smudged) != crlf {
		t.Errorf("CRLF round trip changed the file:\n got  = %q\n want = %q", smudged, crlf)
	}
}

// The property the graceful degrade on `git pull` (spec 06 AC-6.11)
// actually depends on: a Windows clone re-cleaning a document git has
// reintroduced CRLF into must reproduce the exact same ciphertext,
// modulo line endings, as the LF version committed from Linux/macOS —
// otherwise the working tree looks locally modified even though nothing
// meaningful changed, which is exactly the "would be overwritten by
// merge" failure this guards against.
func TestCleanValuesCRLFMatchesLFAfterNormalizing(t *testing.T) {
	crlf := strings.ReplaceAll(valueDoc, "\n", "\r\n")
	cfg := valueConfig("database.password")

	lfCleaned, err := Clean(cfg, testKeyring, "config/staging.yaml", []byte(valueDoc))
	if err != nil {
		t.Fatalf("Clean (LF): %v", err)
	}
	crlfCleaned, err := Clean(cfg, testKeyring, "config/staging.yaml", []byte(crlf))
	if err != nil {
		t.Fatalf("Clean (CRLF): %v", err)
	}

	if normalized := strings.ReplaceAll(string(crlfCleaned), "\r\n", "\n"); normalized != string(lfCleaned) {
		t.Errorf("CRLF clean output, normalized, does not match the LF version:\n got  = %q\n want = %q", normalized, lfCleaned)
	}
}

// AC-6.4: a field that is already tagged is left exactly as it is, rather
// than encrypted a second time.
func TestCleanValuesSkipsAlreadyEncrypted(t *testing.T) {
	once, err := Clean(valueConfig(), testKeyring, "config/staging.yaml", []byte(valueDoc))
	if err != nil {
		t.Fatalf("first clean: %v", err)
	}
	twice, err := Clean(valueConfig(), testKeyring, "config/staging.yaml", once)
	if err != nil {
		t.Fatalf("second clean: %v", err)
	}
	if !bytes.Equal(once, twice) {
		t.Errorf("re-cleaning an encrypted file changed it:\n once  = %s\n twice = %s", once, twice)
	}
}

// The bug this guards against: Clean must not require the current
// version's key merely because a field's value already carries an
// ENC[...] tag from an earlier version — requiring it there would break
// git's routine re-invocation of clean on already-converged content (a
// racily-clean index refresh, `git add -u`, `git status`, `git add
// --renormalize`) for any clone that has fallen behind a rotation it
// hasn't rejoined yet. Nothing here needs encrypting, so nothing here
// should demand a key.
func TestCleanValuesNoKeyNeededWhenNothingToEncrypt(t *testing.T) {
	cfg := valueConfig("database.password")
	// Pre-tag the field under version 1 — this clone, right now, has no
	// key at all, current or otherwise.
	already, err := Clean(cfg, Keyring{1: testKey}, "config/staging.yaml", []byte(valueDoc))
	if err != nil {
		t.Fatalf("clean under v1: %v", err)
	}

	current2 := &config.Config{KeyVersion: 2, Rules: cfg.Rules}
	got, err := Clean(current2, Keyring{}, "config/staging.yaml", already)
	if err != nil {
		t.Fatalf("Clean() with no keys registered: want success (nothing to encrypt), got %v", err)
	}
	if !bytes.Equal(got, already) {
		t.Errorf("Clean() changed already-tagged content: got %q, want unchanged %q", got, already)
	}
}

// The counterpart: a field that still needs encrypting still requires
// the current version's key, even alongside another field in the same
// document that's already tagged and needs no key at all.
func TestCleanValuesStillNeedsKeyForUnencryptedField(t *testing.T) {
	cfg := valueConfig("database.password", "api.token")
	// Pre-tag only database.password, under version 1; api.token is still
	// plaintext.
	partiallyCleaned, err := Clean(valueConfig("database.password"), Keyring{1: testKey}, "config/staging.yaml", []byte(valueDoc))
	if err != nil {
		t.Fatalf("clean under v1: %v", err)
	}

	current2 := &config.Config{KeyVersion: 2, Rules: cfg.Rules}
	if _, err := Clean(current2, Keyring{1: testKey}, "config/staging.yaml", partiallyCleaned); !errors.Is(err, ErrKeyVersionMissing) {
		t.Fatalf("Clean() error = %v, want %v", err, ErrKeyVersionMissing)
	}
}

// AC-6.7: a file whose fields are still plaintext (staged before the
// filter was registered) passes through smudge untouched.
func TestSmudgeValuesTolerantOfPlaintext(t *testing.T) {
	got, _, err := Smudge(valueConfig(), testKeyring, "config/staging.yaml", []byte(valueDoc))
	if err != nil {
		t.Fatalf("Smudge: %v", err)
	}
	if string(got) != valueDoc {
		t.Errorf("Smudge changed an unencrypted file:\n%s", got)
	}
}

// AC-5.2: a configured field the file doesn't contain is an error. Silently
// skipping it would report success while committing that secret in clear.
func TestCleanValuesMissingFieldFails(t *testing.T) {
	_, err := Clean(valueConfig("database.nope"), testKeyring, "config/staging.yaml", []byte(valueDoc))
	if err == nil {
		t.Fatal("Clean with a missing field: want an error, got nil")
	}
	if !strings.Contains(err.Error(), "database.nope") {
		t.Errorf("error does not name the missing field: %v", err)
	}
}

// AC-6.9: a tampered tag is reported, never smudged into plausible-looking
// plaintext.
func TestSmudgeValuesSurfacesTampering(t *testing.T) {
	cleaned, err := Clean(valueConfig(), testKeyring, "config/staging.yaml", []byte(valueDoc))
	if err != nil {
		t.Fatalf("Clean: %v", err)
	}
	// Flip a byte inside the base64 payload.
	idx := bytes.Index(cleaned, []byte("data:")) + len("data:") + 2
	tampered := bytes.Clone(cleaned)
	tampered[idx] ^= 1

	if _, _, err := Smudge(valueConfig(), testKeyring, "config/staging.yaml", tampered); err == nil {
		t.Error("Smudge on a tampered tag: want an error, got nil")
	}
}

// A value sealed for one field must not decrypt in another: the AAD binds
// each ciphertext to its own location, so a tag cannot be copy-pasted.
func TestValueTagIsBoundToItsField(t *testing.T) {
	cleaned, err := Clean(valueConfig("database.password"), testKeyring, "config/staging.yaml", []byte(valueDoc))
	if err != nil {
		t.Fatalf("Clean: %v", err)
	}
	// Move the tag from database.password to api.token.
	tagText := string(cleaned[bytes.Index(cleaned, []byte(`"ENC[`)) : bytes.Index(cleaned, []byte("]\""))+2])
	moved := strings.Replace(valueDoc, "token: alpha", "token: "+tagText, 1)

	if _, _, err := Smudge(valueConfig("api.token"), testKeyring, "config/staging.yaml", []byte(moved)); err == nil {
		t.Error("a tag moved to another field still decrypted")
	}
}

// A file matching a mode: value rule in a format with no handler is an
// error at filter time, not a silent passthrough that would commit the
// secret in clear.
func TestValuesUnsupportedFormatFails(t *testing.T) {
	cfg := &config.Config{Rules: []config.Rule{
		{Files: "config/*.toml", Mode: config.ModeValue, Encrypt: []string{"database.password"}},
	}}
	if _, err := Clean(cfg, testKeyring, "config/staging.toml", []byte("password = 's3cr3t'")); err == nil {
		t.Error("Clean on an unsupported format: want an error, got nil")
	}
}

// A whole-file blob pasted into a value slot has no type to restore;
// guessing one would silently change the document's shape.
func TestSmudgeValuesRejectsUntypedTag(t *testing.T) {
	doc := strings.Replace(valueDoc, `password: "s3cr3t"`, `password: "`+tag.Encode([]byte("whatever"), 1)+`"`, 1)
	if _, _, err := Smudge(valueConfig(), testKeyring, "config/staging.yaml", []byte(doc)); err == nil {
		t.Error("Smudge on an untyped tag: want an error, got nil")
	}
}

// Regression test for the 2026-09-29 audit's P05: a value's type field
// sits next to its ciphertext as plaintext metadata, not inside it, so
// changing type:str to type:bool needs no key at all. Before this fix,
// that silently changed how a decrypted string rendered (a boolean or
// number, unquoted, instead of a quoted string) without tripping SIV's
// own authentication, since the AAD never covered the type field. Now
// that EncodeValue's tag binds Type into the AAD, the same edit must fail
// authentication instead.
func TestSmudgeValuesRejectsTypeTampering(t *testing.T) {
	cleaned, err := Clean(valueConfig(), testKeyring, "config/staging.yaml", []byte(valueDoc))
	if err != nil {
		t.Fatalf("Clean: %v", err)
	}
	if !bytes.Contains(cleaned, []byte(",type:str]")) {
		t.Fatalf("expected a type:str tag, got:\n%s", cleaned)
	}
	tampered := bytes.Replace(cleaned, []byte(",type:str]"), []byte(",type:bool]"), 1)

	if _, _, err := Smudge(valueConfig(), testKeyring, "config/staging.yaml", tampered); !errors.Is(err, siv.ErrAuth) {
		t.Errorf("Smudge() on a type-tampered tag: error = %v, want %v", err, siv.ErrAuth)
	}
}

// Backward compatibility: a value tag committed before this fix
// (AlgoAES256SIV, encrypted with the pre-P05 AAD that never included the
// type) has no in-tool migration and must keep decrypting exactly as it
// always did — see the tag package's doc comment. This hand-builds one
// the way a pre-fix EncodeValue would have, rather than relying on the
// current (now type-bound) EncodeValue.
func TestSmudgeValuesAcceptsLegacyPreTypeBoundTag(t *testing.T) {
	const legacyPassword = "old-secret"
	legacyAAD := siv.AAD(siv.ModeValue, "config/staging.yaml", "database.password")
	ciphertext, err := siv.Encrypt(testKey, []byte(legacyPassword), legacyAAD)
	if err != nil {
		t.Fatalf("siv.Encrypt: %v", err)
	}
	legacyTag := fmt.Sprintf("ENC[%s,key:1,data:%s,type:str]", tag.AlgoAES256SIV, base64.StdEncoding.EncodeToString(ciphertext))

	doc := strings.Replace(valueDoc, `password: "s3cr3t"`, `password: "`+legacyTag+`"`, 1)
	got, _, err := Smudge(valueConfig(), testKeyring, "config/staging.yaml", []byte(doc))
	if err != nil {
		t.Fatalf("Smudge on a legacy pre-type-bound tag: %v", err)
	}
	if !bytes.Contains(got, []byte("password: \""+legacyPassword+"\"")) {
		t.Errorf("Smudge() = %q, want it to decrypt the legacy tag back to %q", got, legacyPassword)
	}
}

// Documents, rather than asserts as desirable, the residual limitation
// backward compatibility with TestSmudgeValuesAcceptsLegacyPreTypeBoundTag
// requires: a *legacy* tag's type field is not authenticated, exactly as
// it always was, since re-authenticating it under the new AAD formula
// would break every such tag already committed before this fix. A legacy
// value converges onto the safer, type-bound form the next time anything
// re-encrypts it (an ordinary edit, `nebel rotate`, or `git add
// --renormalize`) — see the tag package's doc comment. What remains is
// narrower than the original P05 finding, though, not the same gap:
// validTypeLiteral (see TestSmudgeValuesRejectsNonLiteralAfterLegacyTypeFlip)
// refuses a plaintext that isn't a genuine literal for the type it's been
// flipped to, so a flip only "succeeds" — as here — when the underlying
// plaintext happens to also be a valid literal of the new type, same as
// the string "false" is also a valid bool literal.
func TestSmudgeValuesLegacyTagTypeStillUnauthenticated(t *testing.T) {
	const legacyValue = "false"
	legacyAAD := siv.AAD(siv.ModeValue, "config/staging.yaml", "database.password")
	ciphertext, err := siv.Encrypt(testKey, []byte(legacyValue), legacyAAD)
	if err != nil {
		t.Fatalf("siv.Encrypt: %v", err)
	}
	legacyTag := fmt.Sprintf("ENC[%s,key:1,data:%s,type:str]", tag.AlgoAES256SIV, base64.StdEncoding.EncodeToString(ciphertext))
	tamperedTag := strings.Replace(legacyTag, ",type:str]", ",type:bool]", 1)

	doc := strings.Replace(valueDoc, `password: "s3cr3t"`, `password: "`+tamperedTag+`"`, 1)
	got, _, err := Smudge(valueConfig(), testKeyring, "config/staging.yaml", []byte(doc))
	if err != nil {
		t.Fatalf("Smudge on a type-tampered legacy tag: want no error (known limitation), got %v", err)
	}
	if !bytes.Contains(got, []byte("password: "+legacyValue)) {
		t.Errorf("Smudge() = %q, want the unquoted rendering %q the type-flip produces", got, "password: "+legacyValue)
	}
}

// The stopgap validTypeLiteral adds: a legacy tag's type field still
// isn't authenticated (see TestSmudgeValuesLegacyTagTypeStillUnauthenticated),
// but flipping type:str to type:bool on a plaintext that isn't itself a
// valid bool literal — ordinary secret text, not crafted to also read as
// one — must now be refused rather than rendered unquoted. Unquoted
// arbitrary text is exactly how a crafted plaintext could inject
// structure into the surrounding document.
func TestSmudgeValuesRejectsNonLiteralAfterLegacyTypeFlip(t *testing.T) {
	const legacyValue = "s3cr3t"
	legacyAAD := siv.AAD(siv.ModeValue, "config/staging.yaml", "database.password")
	ciphertext, err := siv.Encrypt(testKey, []byte(legacyValue), legacyAAD)
	if err != nil {
		t.Fatalf("siv.Encrypt: %v", err)
	}
	legacyTag := fmt.Sprintf("ENC[%s,key:1,data:%s,type:str]", tag.AlgoAES256SIV, base64.StdEncoding.EncodeToString(ciphertext))
	tamperedTag := strings.Replace(legacyTag, ",type:str]", ",type:bool]", 1)

	doc := strings.Replace(valueDoc, `password: "s3cr3t"`, `password: "`+tamperedTag+`"`, 1)
	if _, _, err := Smudge(valueConfig(), testKeyring, "config/staging.yaml", []byte(doc)); !errors.Is(err, ErrInvalidTypeLiteral) {
		t.Errorf("Smudge() error = %v, want %v", err, ErrInvalidTypeLiteral)
	}
}
