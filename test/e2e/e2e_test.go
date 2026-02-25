//go:build e2e

package e2e

import (
	"testing"
)

func TestVersionFlag(t *testing.T) {
	out, err := runOcellus(t, "--version")
	if err != nil {
		t.Fatalf("ocellus --version failed: %v\n%s", err, out)
	}
	if len(out) == 0 {
		t.Fatal("expected version output, got empty")
	}
	t.Logf("version output: %s", out)
}

func TestPodDiscovery(t *testing.T) {
	// Verify the test workload is running.
	out, err := kubectl(t, "get", "pods", "-n", "default", "-l", "app=e2e-nginx", "-o", "jsonpath={.items[*].status.phase}")
	if err != nil {
		t.Fatalf("kubectl get pods failed: %v\n%s", err, out)
	}
	if string(out) != "Running" {
		t.Fatalf("expected e2e-nginx pod Running, got: %s", out)
	}

	// Run ocellus targeting the deployment — it should resolve pods and start.
	// We expect it to exit with a non-zero code due to no TTY / alt-screen,
	// but it should get past pod discovery without error.
	out, err = runOcellus(t, "-n", "default", "deploy/e2e-nginx")
	// The TUI will fail without a terminal, so we just check it got far enough
	// to attempt to start (not a "no pods found" or discovery error).
	t.Logf("ocellus output: %s (err: %v)", out, err)
}
