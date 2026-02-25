//go:build e2e

package e2e

import (
	"context"
	"os/exec"
	"testing"
	"time"

	"github.com/aurelcanciu/ocellus/internal/cilium"
	"github.com/aurelcanciu/ocellus/internal/k8s"
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

// newRealClient creates a real Kubernetes client using the default kubeconfig.
// It skips the test if no kubeconfig is available.
func newRealClient(t *testing.T) *k8s.Client {
	t.Helper()
	client, err := k8s.NewClient("")
	if err != nil {
		t.Skipf("skipping: no kubeconfig available: %v", err)
	}
	return client
}

// requireNginxPod discovers the e2e-nginx pod and returns its PodInfo.
func requireNginxPod(t *testing.T, client *k8s.Client) k8s.PodInfo {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pods, err := k8s.DiscoverPods(ctx, client, "default", k8s.Target{Kind: "deployment", Name: "e2e-nginx"})
	if err != nil {
		t.Fatalf("discover e2e-nginx pods: %v", err)
	}
	if len(pods) == 0 {
		t.Fatal("no e2e-nginx pods found")
	}
	return pods[0]
}

// requireCiliumAgent finds the Cilium agent pod on the given node.
func requireCiliumAgent(t *testing.T, client *k8s.Client, nodeName string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	agent, err := cilium.FindCiliumAgent(ctx, client, nodeName)
	if err != nil {
		t.Fatalf("find cilium agent on node %s: %v", nodeName, err)
	}
	return agent
}
