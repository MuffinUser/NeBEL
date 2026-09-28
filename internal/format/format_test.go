// Copyright (C) 2026 Marwin Moellers
// SPDX-License-Identifier: GPL-3.0-or-later

package format

import (
	"errors"
	"strings"
	"testing"

	"github.com/MarwinMoellers/nebel/internal/tag"
)

func TestParsePath(t *testing.T) {
	tests := []struct {
		path    string
		want    []Step
		wantErr bool
	}{
		{path: "password", want: []Step{{Key: "password", Index: -1}}},
		{path: "database.password", want: []Step{{Key: "database", Index: -1}, {Key: "password", Index: -1}}},
		{path: "api.keys[0]", want: []Step{{Key: "api", Index: -1}, {Key: "keys", Index: -1}, {Index: 0}}},
		{path: "a[1][2]", want: []Step{{Key: "a", Index: -1}, {Index: 1}, {Index: 2}}},
		{path: "a[0].b", want: []Step{{Key: "a", Index: -1}, {Index: 0}, {Key: "b", Index: -1}}},
		{path: "", wantErr: true},
		{path: "a..b", wantErr: true},
		{path: "a[", wantErr: true},
		{path: "a[x]", wantErr: true},
		{path: "a[-1]", wantErr: true},
		{path: "a[0]junk", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got, err := ParsePath(tt.path)
			if tt.wantErr {
				if !errors.Is(err, ErrBadPath) {
					t.Fatalf("ParsePath(%q) error = %v, want %v", tt.path, err, ErrBadPath)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParsePath(%q): %v", tt.path, err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("ParsePath(%q) = %+v, want %+v", tt.path, got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("step %d = %+v, want %+v", i, got[i], tt.want[i])
				}
			}
		})
	}
}

// The document every locate test runs against: comments, irregular
// indentation and mixed quoting styles, all of which must survive.
const yamlDoc = `# Staging configuration.
database:
  host: db.internal      # not a secret
  password: "s3cr3t"
  port: 5432
  ratio: 1.5
  replica: true

api:
  keys: [alpha, beta]
  token: 'single-quoted'

# trailing comment
`

const jsonDoc = `{
  "database": {
    "host": "db.internal",
    "password": "s3cr3t",
    "port": 5432,
    "ratio": 1.5,
    "replica": true
  },
  "api": { "keys": ["alpha", "beta"] }
}
`

// AC-5.4, AC-5.5, AC-5.7: a dot-path resolves to the right scalar, and the
// span covers exactly that scalar — quotes included, neighbours excluded.
func TestLocate(t *testing.T) {
	tests := []struct {
		name      string
		file      string
		src       string
		path      string
		wantRaw   string
		wantValue string
		wantType  tag.Type
	}{
		{"yaml nested string", "c.yaml", yamlDoc, "database.password", `"s3cr3t"`, "s3cr3t", tag.TypeStr},
		{"yaml plain string", "c.yaml", yamlDoc, "database.host", "db.internal", "db.internal", tag.TypeStr},
		{"yaml single-quoted", "c.yaml", yamlDoc, "api.token", "'single-quoted'", "single-quoted", tag.TypeStr},
		{"yaml int", "c.yaml", yamlDoc, "database.port", "5432", "5432", tag.TypeInt},
		{"yaml float", "c.yaml", yamlDoc, "database.ratio", "1.5", "1.5", tag.TypeFloat},
		{"yaml bool", "c.yaml", yamlDoc, "database.replica", "true", "true", tag.TypeBool},
		{"yaml array index", "c.yaml", yamlDoc, "api.keys[1]", "beta", "beta", tag.TypeStr},
		{"json nested string", "c.json", jsonDoc, "database.password", `"s3cr3t"`, "s3cr3t", tag.TypeStr},
		{"json int", "c.json", jsonDoc, "database.port", "5432", "5432", tag.TypeInt},
		{"json float", "c.json", jsonDoc, "database.ratio", "1.5", "1.5", tag.TypeFloat},
		{"json bool", "c.json", jsonDoc, "database.replica", "true", "true", tag.TypeBool},
		{"json array index", "c.json", jsonDoc, "api.keys[0]", `"alpha"`, "alpha", tag.TypeStr},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, err := For(tt.file)
			if err != nil {
				t.Fatal(err)
			}
			span, err := h.Locate([]byte(tt.src), tt.path)
			if err != nil {
				t.Fatalf("Locate(%q): %v", tt.path, err)
			}
			if got := tt.src[span.Start:span.End]; got != tt.wantRaw {
				t.Errorf("span covers %q, want %q", got, tt.wantRaw)
			}
			if span.Value != tt.wantValue {
				t.Errorf("Value = %q, want %q", span.Value, tt.wantValue)
			}
			if span.Type != tt.wantType {
				t.Errorf("Type = %q, want %q", span.Type, tt.wantType)
			}
		})
	}
}

// AC-5.1: replacing a value leaves every other byte of the file identical —
// comments, key order, indentation, blank lines and unrelated values.
func TestSpliceIsByteExact(t *testing.T) {
	for _, tt := range []struct{ name, file, src, path string }{
		{"yaml", "c.yaml", yamlDoc, "database.password"},
		{"json", "c.json", jsonDoc, "database.password"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			h, err := For(tt.file)
			if err != nil {
				t.Fatal(err)
			}
			span, err := h.Locate([]byte(tt.src), tt.path)
			if err != nil {
				t.Fatal(err)
			}

			const replacement = `"ENC[AES256_SIV,data:AAAA,type:str]"`
			got, err := Splice([]byte(tt.src), []Edit{{Span: span, Text: replacement}})
			if err != nil {
				t.Fatal(err)
			}

			want := tt.src[:span.Start] + replacement + tt.src[span.End:]
			if string(got) != want {
				t.Errorf("splice result:\n got  = %q\n want = %q", got, want)
			}
			// Everything except the replaced scalar must be untouched.
			if before := string(got[:span.Start]); before != tt.src[:span.Start] {
				t.Errorf("bytes before the value changed:\n got  = %q\n want = %q", before, tt.src[:span.Start])
			}
			if after := string(got[span.Start+len(replacement):]); after != tt.src[span.End:] {
				t.Errorf("bytes after the value changed:\n got  = %q\n want = %q", after, tt.src[span.End:])
			}
		})
	}
}

// AC-5.3: several configured paths are replaced in one pass, independently.
func TestSpliceMultipleTargets(t *testing.T) {
	h, err := For("c.yaml")
	if err != nil {
		t.Fatal(err)
	}

	var edits []Edit
	for _, path := range []string{"database.password", "database.port", "api.keys[1]"} {
		span, err := h.Locate([]byte(yamlDoc), path)
		if err != nil {
			t.Fatalf("Locate(%q): %v", path, err)
		}
		edits = append(edits, Edit{Span: span, Text: `"X"`})
	}

	got, err := Splice([]byte(yamlDoc), edits)
	if err != nil {
		t.Fatal(err)
	}
	for _, gone := range []string{`"s3cr3t"`, "5432", "beta"} {
		if strings.Contains(string(got), gone) {
			t.Errorf("value %q survived the splice:\n%s", gone, got)
		}
	}
	for _, kept := range []string{"# Staging configuration.", "db.internal      # not a secret", "alpha", "# trailing comment"} {
		if !strings.Contains(string(got), kept) {
			t.Errorf("untouched content %q was lost:\n%s", kept, got)
		}
	}
}

// AC-5.2: a configured path that isn't in the file is an error, never a
// silent no-op that would leave the secret in plaintext.
func TestLocateMissingPath(t *testing.T) {
	for _, tt := range []struct{ name, file, src, path string }{
		{"yaml missing key", "c.yaml", yamlDoc, "database.missing"},
		{"yaml missing parent", "c.yaml", yamlDoc, "nope.password"},
		{"yaml index out of range", "c.yaml", yamlDoc, "api.keys[9]"},
		{"json missing key", "c.json", jsonDoc, "database.missing"},
		{"json missing parent", "c.json", jsonDoc, "nope.password"},
		{"json index out of range", "c.json", jsonDoc, "api.keys[9]"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			h, err := For(tt.file)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := h.Locate([]byte(tt.src), tt.path); !errors.Is(err, ErrNotFound) {
				t.Errorf("Locate(%q) error = %v, want %v", tt.path, err, ErrNotFound)
			}
		})
	}
}

// A path pointing at a mapping or sequence is a config mistake: encrypting
// a subtree as one scalar would silently destroy its structure.
func TestLocateRejectsNonScalar(t *testing.T) {
	for _, tt := range []struct{ name, file, src, path string }{
		{"yaml mapping", "c.yaml", yamlDoc, "database"},
		{"yaml sequence", "c.yaml", yamlDoc, "api.keys"},
		{"json object", "c.json", jsonDoc, "database"},
		{"json array", "c.json", jsonDoc, "api.keys"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			h, err := For(tt.file)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := h.Locate([]byte(tt.src), tt.path); !errors.Is(err, ErrNotScalar) {
				t.Errorf("Locate(%q) error = %v, want %v", tt.path, err, ErrNotScalar)
			}
		})
	}
}

// Render is the decryption side: a restored value must come back with its
// original type, not as a quoted string (AC-3.2).
func TestRender(t *testing.T) {
	tests := []struct {
		file, value string
		typ         tag.Type
		want        string
	}{
		{"c.yaml", "s3cr3t", tag.TypeStr, `"s3cr3t"`},
		{"c.yaml", "5432", tag.TypeInt, "5432"},
		{"c.yaml", "1.5", tag.TypeFloat, "1.5"},
		{"c.yaml", "true", tag.TypeBool, "true"},
		{"c.yaml", `say "hi"`, tag.TypeStr, `"say \"hi\""`},
		{"c.json", "s3cr3t", tag.TypeStr, `"s3cr3t"`},
		{"c.json", "5432", tag.TypeInt, "5432"},
		{"c.json", `say "hi"`, tag.TypeStr, `"say \"hi\""`},
	}

	for _, tt := range tests {
		t.Run(tt.file+"/"+tt.value+"/"+string(tt.typ), func(t *testing.T) {
			h, err := For(tt.file)
			if err != nil {
				t.Fatal(err)
			}
			if got := h.Render(tt.value, tt.typ); got != tt.want {
				t.Errorf("Render(%q, %q) = %s, want %s", tt.value, tt.typ, got, tt.want)
			}
		})
	}
}

func TestForUnsupportedExtension(t *testing.T) {
	if _, err := For("secrets.toml"); !errors.Is(err, ErrUnsupportedFormat) {
		t.Errorf("For() error = %v, want %v", err, ErrUnsupportedFormat)
	}
}

// Leaves is what `nebel add field` offers to pick from, so it must
// list every scalar — and only scalars — with a path that Locate accepts.
func TestLeaves(t *testing.T) {
	tests := []struct {
		name, file, src string
		want            []string
	}{
		{"yaml", "c.yaml", yamlDoc, []string{
			"database.host", "database.password", "database.port", "database.ratio",
			"database.replica", "api.keys[0]", "api.keys[1]", "api.token",
		}},
		{"json", "c.json", jsonDoc, []string{
			"database.host", "database.password", "database.port", "database.ratio",
			"database.replica", "api.keys[0]", "api.keys[1]",
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, err := For(tt.file)
			if err != nil {
				t.Fatal(err)
			}
			leaves, err := h.Leaves([]byte(tt.src))
			if err != nil {
				t.Fatalf("Leaves: %v", err)
			}

			var got []string
			for _, leaf := range leaves {
				got = append(got, leaf.Path)
			}
			if strings.Join(got, ",") != strings.Join(tt.want, ",") {
				t.Errorf("Leaves() paths =\n %v\nwant\n %v", got, tt.want)
			}

			// Every offered path must actually resolve, or the picker
			// would hand the user a path that fails at clean time.
			for _, leaf := range leaves {
				span, err := h.Locate([]byte(tt.src), leaf.Path)
				if err != nil {
					t.Errorf("Locate(%q) from Leaves: %v", leaf.Path, err)
					continue
				}
				if span.Value != leaf.Value {
					t.Errorf("%s: Leaves value %q, Locate value %q", leaf.Path, leaf.Value, span.Value)
				}
				if span.Type != leaf.Type {
					t.Errorf("%s: Leaves type %q, Locate type %q", leaf.Path, leaf.Type, span.Type)
				}
			}
		})
	}
}
