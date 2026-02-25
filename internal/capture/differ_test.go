package capture

import (
	"testing"
	"time"

	"github.com/nex-health/ocellus/internal/cilium"
)

func TestDiffPeerAdded(t *testing.T) {
	ts := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	prev := &Snapshot{
		Timestamp: ts,
		Pods:      map[string][]cilium.Peer{"pod-1": {}},
	}
	curr := Snapshot{
		Timestamp: ts.Add(10 * time.Second),
		Pods: map[string][]cilium.Peer{
			"pod-1": {{Src: "10.0.0.1:1000", DstPort: 5432}},
		},
	}
	events := Diff(prev, curr)
	found := false
	for _, e := range events {
		if e.Kind == EventPeerAdded && e.Pod == "pod-1" && e.Peer.Src == "10.0.0.1:1000" {
			found = true
		}
	}
	if !found {
		t.Error("expected peer_added event for 10.0.0.1:1000")
	}
}

func TestDiffPeerRemoved(t *testing.T) {
	ts := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	prev := &Snapshot{
		Timestamp: ts,
		Pods: map[string][]cilium.Peer{
			"pod-1": {{Src: "10.0.0.1:1000", DstPort: 5432}},
		},
	}
	curr := Snapshot{
		Timestamp: ts.Add(10 * time.Second),
		Pods:      map[string][]cilium.Peer{"pod-1": {}},
	}
	events := Diff(prev, curr)
	found := false
	for _, e := range events {
		if e.Kind == EventPeerRemoved && e.Pod == "pod-1" {
			found = true
		}
	}
	if !found {
		t.Error("expected peer_removed event")
	}
}

func TestDiffPodDiscovered(t *testing.T) {
	ts := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	prev := &Snapshot{
		Timestamp: ts,
		Pods:      map[string][]cilium.Peer{},
	}
	curr := Snapshot{
		Timestamp: ts.Add(10 * time.Second),
		Pods: map[string][]cilium.Peer{
			"pod-1": {{Src: "10.0.0.1:1000"}},
		},
	}
	events := Diff(prev, curr)
	found := false
	for _, e := range events {
		if e.Kind == EventPodDiscovered && e.Pod == "pod-1" {
			found = true
		}
	}
	if !found {
		t.Error("expected pod_discovered event")
	}
}

func TestDiffPodExited(t *testing.T) {
	ts := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	prev := &Snapshot{
		Timestamp: ts,
		Exited:    map[string]bool{},
	}
	curr := Snapshot{
		Timestamp: ts.Add(10 * time.Second),
		Exited:    map[string]bool{"pod-1": true},
	}
	events := Diff(prev, curr)
	found := false
	for _, e := range events {
		if e.Kind == EventPodExited && e.Pod == "pod-1" {
			found = true
		}
	}
	if !found {
		t.Error("expected pod_exited event")
	}
}

func TestDiffNilPrev(t *testing.T) {
	curr := Snapshot{
		Timestamp: time.Now(),
		Pods: map[string][]cilium.Peer{
			"pod-1": {{Src: "10.0.0.1:1000"}},
		},
	}
	events := Diff(nil, curr)
	found := false
	for _, e := range events {
		if e.Kind == EventPodDiscovered {
			found = true
		}
	}
	if !found {
		t.Error("expected pod_discovered event on first snapshot")
	}
}

func TestDiffPollError(t *testing.T) {
	ts := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	prev := &Snapshot{Timestamp: ts}
	curr := Snapshot{
		Timestamp: ts.Add(10 * time.Second),
		Errors:    []string{"node-a: timeout"},
	}
	events := Diff(prev, curr)
	found := false
	for _, e := range events {
		if e.Kind == EventPollError && e.Message == "node-a: timeout" {
			found = true
		}
	}
	if !found {
		t.Error("expected poll_error event")
	}
}

func TestDiffTrafficSpike(t *testing.T) {
	ts := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	prev := &Snapshot{
		Timestamp: ts,
		Pods: map[string][]cilium.Peer{
			"pod-1": {{Src: "10.0.0.1:1000", Bytes: 1000}},
		},
	}
	curr := Snapshot{
		Timestamp: ts.Add(10 * time.Second),
		Pods: map[string][]cilium.Peer{
			"pod-1": {{Src: "10.0.0.1:1000", Bytes: 5000}},
		},
	}
	events := Diff(prev, curr)
	found := false
	for _, e := range events {
		if e.Kind == EventTrafficSpike && e.Pod == "pod-1" {
			found = true
		}
	}
	if !found {
		t.Error("expected traffic_spike event (5x increase)")
	}
}
