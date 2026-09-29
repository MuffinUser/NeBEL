// Copyright (C) 2026 Marwin Moellers
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"strings"
	"testing"

	"github.com/MuffinUser/nebel/internal/config"
	"github.com/MuffinUser/nebel/internal/gitutil"
)

// audit 2026-09-29, P12: previously, reportCheckoutResult printed a
// genuine per-file checkout failure (AC-6.9 tamper/corruption) but always
// returned nil, so a script relying on the exit code alone couldn't tell
// init left unusable content behind.
func TestReportCheckoutResultFailsOnGenuineCheckoutFailure(t *testing.T) {
	pathEnv := pathEnvWithBin(t)
	root := newTestRepo(t, pathEnv)
	cfg := &config.Config{KeyVersion: 1, Rules: []config.Rule{}}

	err := reportCheckoutResult(root, cfg, 0, []gitutil.CheckoutFailure{
		{Path: "secrets/prod.pem", Reason: "authentication failed"},
	})
	if err == nil {
		t.Fatal("reportCheckoutResult returned nil despite a genuine checkout failure")
	}
	if !strings.Contains(err.Error(), "1 file") {
		t.Errorf("error = %v, want it to mention the failure count", err)
	}
}

// The AC-6.11 passthrough case (a file that only needs a key version this
// clone hasn't fetched yet) is unaffected by the fix above — it must keep
// exiting 0, matching TestInitVersionRecoversContentFromBeforeRotation's
// expectation that this is a recoverable, expected state, not a failure.
func TestReportCheckoutResultSucceedsWhenOnlyMissingKeyVersion(t *testing.T) {
	pathEnv := pathEnvWithBin(t)
	root := newTestRepo(t, pathEnv)
	cfg := &config.Config{KeyVersion: 1, Rules: []config.Rule{}}

	if err := reportCheckoutResult(root, cfg, 3, nil); err != nil {
		t.Fatalf("unexpected error with no genuine failures: %v", err)
	}
}
