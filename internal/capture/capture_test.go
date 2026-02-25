package capture

import (
	"testing"
	"time"

	"github.com/nex-health/ocellus/internal/cilium"
)

func TestSnapshotHasTimestamp(t *testing.T) {
	ts := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	s := Snapshot{
		Timestamp: ts,
		Pods: map[string][]cilium.Peer{
			"pod-1": {{Src: "10.0.0.1:1000", DstPort: 5432, Proto: "TCP", State: "established"}},
		},
	}
	if s.Timestamp != ts {
		t.Errorf("timestamp = %v, want %v", s.Timestamp, ts)
	}
	if len(s.Pods["pod-1"]) != 1 {
		t.Errorf("pod-1 peers = %d, want 1", len(s.Pods["pod-1"]))
	}
}

func TestEventKindValues(t *testing.T) {
	kinds := []EventKind{
		EventPeerAdded, EventPeerRemoved,
		EventPodDiscovered, EventPodExited,
		EventPollError, EventTrafficSpike,
	}
	seen := make(map[EventKind]bool)
	for _, k := range kinds {
		if seen[k] {
			t.Errorf("duplicate event kind: %s", k)
		}
		seen[k] = true
		if k == "" {
			t.Error("event kind should not be empty")
		}
	}
}
