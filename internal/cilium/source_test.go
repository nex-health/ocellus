package cilium

import (
	"context"
	"testing"
)

func TestTextSourceQueryPeers(t *testing.T) {
	client := &mockPodExecer{
		execFn: func(_, _, _ string, _ []string) (string, error) {
			return sampleCTOutput, nil
		},
	}
	src := &TextSource{}
	results, err := src.QueryPeers(context.Background(), client, "cilium-abc", []string{"10.4.34.6"}, Filter{PortMin: 4143, PortMax: 4143})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	peers := results["10.4.34.6"]
	if len(peers) != 3 {
		t.Fatalf("expected 3 peers, got %d", len(peers))
	}
	if peers[0].Bytes == 0 {
		t.Error("expected non-zero Bytes")
	}
}
