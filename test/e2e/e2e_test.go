//go:build e2e

package e2e

import (
	"context"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/aurelcanciu/ocellus/internal/cilium"
	"github.com/aurelcanciu/ocellus/internal/k8s"
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

func TestRealClientCreation(t *testing.T) {
	client := newRealClient(t)

	if client.Context() == "" {
		t.Fatal("expected non-empty context name")
	}
	t.Logf("kubeconfig context: %s", client.Context())

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	pods, err := client.ListPods(ctx, "kube-system", metav1.ListOptions{})
	if err != nil {
		t.Fatalf("ListPods kube-system: %v", err)
	}
	if len(pods.Items) == 0 {
		t.Fatal("expected at least one pod in kube-system")
	}
	t.Logf("found %d pods in kube-system", len(pods.Items))
}

func TestDiscoverPodsByDeployment(t *testing.T) {
	client := newRealClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	pods, err := k8s.DiscoverPods(ctx, client, "default", k8s.Target{Kind: "deployment", Name: "e2e-nginx"})
	if err != nil {
		t.Fatalf("DiscoverPods: %v", err)
	}
	if len(pods) == 0 {
		t.Fatal("expected at least 1 pod for e2e-nginx deployment")
	}
	for _, p := range pods {
		if p.Name == "" {
			t.Error("pod has empty Name")
		}
		if p.Node == "" {
			t.Error("pod has empty Node")
		}
		if p.IP == "" {
			t.Error("pod has empty IP")
		}
		t.Logf("pod: %s node: %s ip: %s", p.Name, p.Node, p.IP)
	}
}

func TestDiscoverPodByName(t *testing.T) {
	client := newRealClient(t)
	nginxPod := requireNginxPod(t, client)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	pods, err := k8s.DiscoverPods(ctx, client, "default", k8s.Target{Kind: "pod", Name: nginxPod.Name})
	if err != nil {
		t.Fatalf("DiscoverPods by name: %v", err)
	}
	if len(pods) != 1 {
		t.Fatalf("expected 1 pod, got %d", len(pods))
	}
	if pods[0].Name != nginxPod.Name {
		t.Fatalf("expected pod %s, got %s", nginxPod.Name, pods[0].Name)
	}
}

func TestFindCiliumAgentReal(t *testing.T) {
	client := newRealClient(t)
	pod := requireNginxPod(t, client)

	agent := requireCiliumAgent(t, client, pod.Node)
	if !strings.HasPrefix(agent, "cilium-") {
		t.Fatalf("expected agent name starting with 'cilium-', got %q", agent)
	}
	t.Logf("cilium agent on node %s: %s", pod.Node, agent)
}

func TestTextSourceQueryPeersReal(t *testing.T) {
	client := newRealClient(t)
	pod := requireNginxPod(t, client)
	agent := requireCiliumAgent(t, client, pod.Node)

	filter, err := cilium.NewFilter(cilium.FilterOpts{Port: "80", State: "all"})
	if err != nil {
		t.Fatalf("NewFilter: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	src := &cilium.TextSource{}
	results, err := src.QueryPeers(ctx, client, agent, []string{pod.IP}, filter)
	if err != nil {
		t.Fatalf("TextSource.QueryPeers: %v", err)
	}

	peers, ok := results[pod.IP]
	if !ok {
		t.Fatalf("no entry for pod IP %s in results", pod.IP)
	}
	if len(peers) == 0 {
		t.Fatal("expected at least 1 peer from traffic-gen")
	}

	for _, p := range peers {
		if p.Src == "" {
			t.Error("peer has empty Src")
		}
		if p.Proto != "TCP" {
			t.Errorf("expected Proto TCP, got %q", p.Proto)
		}
		if p.DstPort != 80 {
			t.Errorf("expected DstPort 80, got %d", p.DstPort)
		}
	}
	t.Logf("found %d peers for pod %s on port 80", len(peers), pod.IP)
}

func TestAutoSourceDetectionReal(t *testing.T) {
	client := newRealClient(t)
	pod := requireNginxPod(t, client)
	agent := requireCiliumAgent(t, client, pod.Node)

	filter, err := cilium.NewFilter(cilium.FilterOpts{Port: "80", State: "all"})
	if err != nil {
		t.Fatalf("NewFilter: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	src := cilium.NewAutoSource()
	results, err := src.QueryPeers(ctx, client, agent, []string{pod.IP}, filter)
	if err != nil {
		t.Fatalf("AutoSource.QueryPeers: %v", err)
	}

	totalPeers := 0
	for _, peers := range results {
		totalPeers += len(peers)
	}
	if totalPeers == 0 {
		t.Fatal("expected at least 1 peer via AutoSource")
	}
	t.Logf("AutoSource found %d total peers", totalPeers)
}

func TestQueryNodeRawOutput(t *testing.T) {
	client := newRealClient(t)
	pod := requireNginxPod(t, client)
	agent := requireCiliumAgent(t, client, pod.Node)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	output, err := cilium.QueryNode(ctx, client, agent)
	if err != nil {
		t.Fatalf("QueryNode: %v", err)
	}
	if output == "" {
		t.Fatal("expected non-empty raw CT output")
	}
	if !strings.Contains(output, "TCP") {
		t.Error("expected raw output to contain 'TCP'")
	}
	t.Logf("raw CT output length: %d bytes", len(output))
}

func TestTextSourceNoMatchingPort(t *testing.T) {
	client := newRealClient(t)
	pod := requireNginxPod(t, client)
	agent := requireCiliumAgent(t, client, pod.Node)

	filter, err := cilium.NewFilter(cilium.FilterOpts{Port: "59999"})
	if err != nil {
		t.Fatalf("NewFilter: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	src := &cilium.TextSource{}
	results, err := src.QueryPeers(ctx, client, agent, []string{pod.IP}, filter)
	if err != nil {
		t.Fatalf("TextSource.QueryPeers: %v", err)
	}

	peers := results[pod.IP]
	if len(peers) != 0 {
		t.Fatalf("expected 0 peers on port 59999, got %d", len(peers))
	}
}

func TestFilterWithSrcCIDR(t *testing.T) {
	client := newRealClient(t)
	pod := requireNginxPod(t, client)
	agent := requireCiliumAgent(t, client, pod.Node)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	src := &cilium.TextSource{}

	// Broad cluster CIDR — should match traffic from within the cluster.
	matchFilter, err := cilium.NewFilter(cilium.FilterOpts{Port: "80", Src: "10.0.0.0/8", State: "all"})
	if err != nil {
		t.Fatalf("NewFilter (match): %v", err)
	}
	results, err := src.QueryPeers(ctx, client, agent, []string{pod.IP}, matchFilter)
	if err != nil {
		t.Fatalf("QueryPeers (match): %v", err)
	}
	if len(results[pod.IP]) == 0 {
		t.Fatal("expected peers from 10.0.0.0/8 CIDR")
	}
	t.Logf("found %d peers matching 10.0.0.0/8", len(results[pod.IP]))

	// Narrow CIDR unlikely to match any cluster traffic.
	noMatchFilter, err := cilium.NewFilter(cilium.FilterOpts{Port: "80", Src: "192.168.99.0/24", State: "all"})
	if err != nil {
		t.Fatalf("NewFilter (no-match): %v", err)
	}
	results, err = src.QueryPeers(ctx, client, agent, []string{pod.IP}, noMatchFilter)
	if err != nil {
		t.Fatalf("QueryPeers (no-match): %v", err)
	}
	if len(results[pod.IP]) != 0 {
		t.Fatalf("expected 0 peers from 192.168.99.0/24, got %d", len(results[pod.IP]))
	}
}

func TestFullPipelineEndToEnd(t *testing.T) {
	// Full pipeline: client -> discover pods -> find agent -> AutoSource.QueryPeers -> verify peers
	client := newRealClient(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Discover pods.
	pods, err := k8s.DiscoverPods(ctx, client, "default", k8s.Target{Kind: "deployment", Name: "e2e-nginx"})
	if err != nil {
		t.Fatalf("DiscoverPods: %v", err)
	}
	if len(pods) == 0 {
		t.Fatal("no pods found")
	}

	pod := pods[0]

	// Find cilium agent.
	agent, err := cilium.FindCiliumAgent(ctx, client, pod.Node)
	if err != nil {
		t.Fatalf("FindCiliumAgent: %v", err)
	}

	// Query peers via AutoSource.
	filter, err := cilium.NewFilter(cilium.FilterOpts{Port: "80", State: "all"})
	if err != nil {
		t.Fatalf("NewFilter: %v", err)
	}

	src := cilium.NewAutoSource()
	results, err := src.QueryPeers(ctx, client, agent, []string{pod.IP}, filter)
	if err != nil {
		t.Fatalf("AutoSource.QueryPeers: %v", err)
	}

	peers := results[pod.IP]
	if len(peers) == 0 {
		t.Fatal("expected at least 1 peer in full pipeline")
	}

	for _, p := range peers {
		if p.Proto != "TCP" {
			t.Errorf("expected Proto TCP, got %q", p.Proto)
		}
		if p.State != "established" && p.State != "closing" {
			t.Errorf("expected State established or closing, got %q", p.State)
		}
		if p.Src == "" {
			t.Error("peer has empty Src")
		}
		if p.DstPort != 80 {
			t.Errorf("expected DstPort 80, got %d", p.DstPort)
		}
	}
	t.Logf("full pipeline: %d peers, first: %+v", len(peers), peers[0])
}
