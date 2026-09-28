#!/bin/sh
# Copyright (C) 2026 Marwin Moellers
# SPDX-License-Identifier: GPL-3.0-or-later
# Regenerate THIRD_PARTY_NOTICES.md from the licence files Go already
# downloaded into the module cache, so the texts are verbatim upstream.
set -eu
cache="$(go env GOMODCACHE)"
out=THIRD_PARTY_NOTICES.md

{
  echo "# Third-party notices"
  echo
  echo "nebel itself is licensed under the GNU General Public License v3.0"
  echo "or later (see \`LICENSE\`). The binary statically links the Go modules"
  echo "listed below; their licences are reproduced verbatim as those licences"
  echo "require. This file is generated — see \`go.mod\` for the authoritative"
  echo "dependency list."
  echo
  echo "| Module | Version | Licence |"
  echo "| --- | --- | --- |"
} > "$out"

# module@version -> SPDX id, in go.mod order
set -- \
  "github.com/bmatcuk/doublestar/v4@v4.10.2:MIT" \
  "github.com/goccy/go-yaml@v1.19.2:MIT" \
  "github.com/tink-crypto/tink-go/v2@v2.8.0:Apache-2.0" \
  "golang.org/x/crypto@v0.57.0:BSD-3-Clause" \
  "golang.org/x/term@v0.46.0:BSD-3-Clause" \
  "golang.org/x/sys@v0.48.0:BSD-3-Clause" \
  "google.golang.org/protobuf@v1.36.11:BSD-3-Clause"

for entry in "$@"; do
  mv="${entry%:*}"; spdx="${entry##*:}"
  mod="${mv%@*}"; ver="${mv##*@}"
  echo "| \`$mod\` | $ver | $spdx |" >> "$out"
done

for entry in "$@"; do
  mv="${entry%:*}"; spdx="${entry##*:}"
  mod="${mv%@*}"; ver="${mv##*@}"
  src="$cache/$mv/LICENSE"
  [ -f "$src" ] || { echo "missing licence file: $src" >&2; exit 1; }
  {
    echo
    echo "---"
    echo
    echo "## $mod $ver"
    echo
    echo "$spdx"
    echo
    echo '```'
    cat "$src"
    echo '```'
  } >> "$out"
done

echo "wrote $out"
