#!/bin/sh
# Copyright (C) 2026 Marwin Moellers
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Installs nebel from a GitHub release, for macOS and Linux:
#
#   curl -fsSL https://raw.githubusercontent.com/MuffinUser/NeBEL/main/scripts/install.sh | sh
#   wget -qO- https://raw.githubusercontent.com/MuffinUser/NeBEL/main/scripts/install.sh | sh
#
# Env vars:
#   NEBEL_VERSION      tag to install, e.g. v0.5.2 (default: latest release)
#   NEBEL_INSTALL_DIR  where to put the binary (default: /usr/local/bin)
set -eu

repo="MuffinUser/NeBEL"

main() {
	os="$(detect_os)"
	arch="$(detect_arch)"
	version="${NEBEL_VERSION:-$(latest_version)}"
	install_dir="${NEBEL_INSTALL_DIR:-/usr/local/bin}"

	asset="nebel_${version}_${os}_${arch}.tar.gz"
	base_url="https://github.com/${repo}/releases/download/${version}"

	tmp="$(mktemp -d)"
	trap 'rm -rf "$tmp"' EXIT INT TERM

	echo "nebel: downloading ${asset} (${version})" >&2
	fetch "${base_url}/${asset}" "${tmp}/${asset}"
	fetch "${base_url}/checksums.txt" "${tmp}/checksums.txt"
	verify_checksum "${tmp}" "${asset}"

	tar -xzf "${tmp}/${asset}" -C "${tmp}"
	extracted_bin="$(find "${tmp}" -type f -name nebel | head -n1)"
	if [ -z "${extracted_bin}" ]; then
		echo "nebel: couldn't find the nebel binary inside ${asset}" >&2
		exit 1
	fi

	mkdir -p "${install_dir}" 2>/dev/null || sudo mkdir -p "${install_dir}"
	if [ -w "${install_dir}" ]; then
		cp "${extracted_bin}" "${install_dir}/nebel"
	else
		echo "nebel: ${install_dir} isn't writable, asking for sudo" >&2
		sudo cp "${extracted_bin}" "${install_dir}/nebel"
	fi
	chmod +x "${install_dir}/nebel" 2>/dev/null || sudo chmod +x "${install_dir}/nebel"

	# Harmless on Linux (attribute doesn't exist) and on files that were
	# never quarantined; only matters for the Gatekeeper mark macOS adds
	# to files written by a browser download, which curl/wget don't set
	# in the first place — kept as a no-op safety net.
	if command -v xattr >/dev/null 2>&1; then
		xattr -d com.apple.quarantine "${install_dir}/nebel" 2>/dev/null || true
	fi

	echo "nebel: installed to ${install_dir}/nebel" >&2
	case ":${PATH}:" in
	*":${install_dir}:"*) ;;
	*)
		echo "nebel: ${install_dir} is not on your PATH — add it, then open a new shell" >&2
		;;
	esac

	"${install_dir}/nebel" version
	if command -v nebel >/dev/null 2>&1; then
		installed_path="$(command -v nebel)"
		if [ "${installed_path}" != "${install_dir}/nebel" ]; then
			echo "nebel: warning — 'nebel' on your PATH resolves to ${installed_path}, not ${install_dir}/nebel" >&2
		fi
	fi
}

detect_os() {
	case "$(uname -s)" in
	Darwin) echo darwin ;;
	Linux) echo linux ;;
	*)
		echo "nebel: unsupported OS $(uname -s) — see README.md for manual install" >&2
		exit 1
		;;
	esac
}

detect_arch() {
	# Under Rosetta, uname -m reports x86_64 even on Apple Silicon;
	# sysctl.proc_translated is the documented way to detect that and
	# install the native arm64 build instead.
	if command -v sysctl >/dev/null 2>&1 && [ "$(sysctl -n sysctl.proc_translated 2>/dev/null || echo 0)" = "1" ]; then
		echo arm64
		return
	fi
	case "$(uname -m)" in
	arm64 | aarch64) echo arm64 ;;
	x86_64 | amd64) echo amd64 ;;
	*)
		echo "nebel: unsupported architecture $(uname -m) — see README.md for manual install" >&2
		exit 1
		;;
	esac
}

# Resolves to the tag name of the latest release via the redirect target
# of /releases/latest, so it isn't subject to the GitHub API's 60
# requests/hour unauthenticated rate limit. Falls back to the API only
# when wget is used, since wget has no easy way to read the final
# redirect URL without the response headers.
latest_version() {
	if command -v curl >/dev/null 2>&1; then
		url="$(curl -fsSLI -o /dev/null -w '%{url_effective}' "https://github.com/${repo}/releases/latest")"
		tag="${url##*/}"
		if [ -z "${tag}" ] || [ "${tag}" = "latest" ]; then
			echo "nebel: couldn't resolve the latest release tag" >&2
			exit 1
		fi
		echo "${tag}"
	elif command -v wget >/dev/null 2>&1; then
		tag="$(wget -qO- "https://api.github.com/repos/${repo}/releases/latest" | grep -m1 '"tag_name"' | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/')"
		if [ -z "${tag}" ]; then
			echo "nebel: couldn't resolve the latest release tag" >&2
			exit 1
		fi
		echo "${tag}"
	else
		echo "nebel: need curl or wget" >&2
		exit 1
	fi
}

fetch() {
	url="$1"
	dest="$2"
	if command -v curl >/dev/null 2>&1; then
		curl -fsSL -o "${dest}" "${url}"
	elif command -v wget >/dev/null 2>&1; then
		wget -qO "${dest}" "${url}"
	else
		echo "nebel: need curl or wget" >&2
		exit 1
	fi
}

verify_checksum() {
	dir="$1"
	asset="$2"
	expected="$(grep " ${asset}\$" "${dir}/checksums.txt" | cut -d' ' -f1)"
	if [ -z "${expected}" ]; then
		echo "nebel: no checksum entry for ${asset} in checksums.txt" >&2
		exit 1
	fi
	if command -v shasum >/dev/null 2>&1; then
		actual="$(shasum -a 256 "${dir}/${asset}" | cut -d' ' -f1)"
	elif command -v sha256sum >/dev/null 2>&1; then
		actual="$(sha256sum "${dir}/${asset}" | cut -d' ' -f1)"
	else
		echo "nebel: need shasum or sha256sum to verify the download" >&2
		exit 1
	fi
	if [ "${expected}" != "${actual}" ]; then
		echo "nebel: checksum mismatch for ${asset}" >&2
		echo "  expected ${expected}" >&2
		echo "  actual   ${actual}" >&2
		exit 1
	fi
}

main "$@"
