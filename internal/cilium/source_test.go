package cilium

import (
	"context"
	"fmt"
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

func TestAutoSourceFallsBackToText(t *testing.T) {
	callCount := 0
	client := &mockPodExecer{
		execFn: func(_, _, _ string, cmd []string) (string, error) {
			callCount++
			// First call with -o json fails (old Cilium).
			for _, arg := range cmd {
				if arg == "json" {
					return "", fmt.Errorf("unknown flag: -o")
				}
			}
			// Second call without -o json succeeds.
			return sampleCTOutput, nil
		},
	}
	src := NewAutoSource()
	results, err := src.QueryPeers(context.Background(), client, "cilium-abc", []string{"10.4.34.6"}, Filter{PortMin: 4143, PortMax: 4143})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	peers := results["10.4.34.6"]
	if len(peers) != 3 {
		t.Fatalf("expected 3 peers, got %d", len(peers))
	}
	if callCount != 2 {
		t.Errorf("expected 2 exec calls (json attempt + text fallback), got %d", callCount)
	}
}

func TestAutoSourceRemembersPreference(t *testing.T) {
	callCount := 0
	client := &mockPodExecer{
		execFn: func(_, _, _ string, cmd []string) (string, error) {
			callCount++
			for _, arg := range cmd {
				if arg == "json" {
					return "", fmt.Errorf("unknown flag: -o")
				}
			}
			return sampleCTOutput, nil
		},
	}
	src := NewAutoSource()
	// First call: tries JSON, falls back to text (2 calls).
	_, _ = src.QueryPeers(context.Background(), client, "cilium-abc", []string{"10.4.34.6"}, Filter{PortMin: 4143, PortMax: 4143})
	if callCount != 2 {
		t.Fatalf("first call: expected 2 exec calls, got %d", callCount)
	}
	// Second call: goes straight to text (1 more call).
	_, _ = src.QueryPeers(context.Background(), client, "cilium-abc", []string{"10.4.34.6"}, Filter{PortMin: 4143, PortMax: 4143})
	if callCount != 3 {
		t.Errorf("second call: expected 3 total exec calls, got %d", callCount)
	}
}
