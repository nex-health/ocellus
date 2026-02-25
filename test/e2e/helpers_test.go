//go:build e2e

package e2e

import (
	"context"
	"os/exec"
	"testing"
	"time"
)

// runOcellus runs the ocellus binary with the given args and a short timeout.
// It returns the combined output. The binary is expected to be built at
// ../../ocellus (repo root) before tests run.
func runOcellus(t *testing.T, args ...string) ([]byte, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "../../ocellus", args...)
	return cmd.CombinedOutput()
}

// kubectl runs a kubectl command and returns combined output.
func kubectl(t *testing.T, args ...string) ([]byte, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "kubectl", args...)
	return cmd.CombinedOutput()
}
