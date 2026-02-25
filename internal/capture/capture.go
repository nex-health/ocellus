package capture

import (
	"time"

	"github.com/nex-health/ocellus/internal/cilium"
)

// Snapshot represents the complete connection state at a moment in time.
type Snapshot struct {
	Timestamp time.Time                `json:"timestamp"`
	Pods      map[string][]cilium.Peer `json:"pods"`
	Exited    map[string]bool          `json:"exited,omitempty"`
	Errors    []string                 `json:"errors,omitempty"`
}

// EventKind identifies the type of event detected by diffing snapshots.
type EventKind string

const (
	EventPeerAdded     EventKind = "peer_added"
	EventPeerRemoved   EventKind = "peer_removed"
	EventPodDiscovered EventKind = "pod_discovered"
	EventPodExited     EventKind = "pod_exited"
	EventPollError     EventKind = "poll_error"
	EventTrafficSpike  EventKind = "traffic_spike"
)

// Event represents a discrete occurrence detected by comparing snapshots.
type Event struct {
	Timestamp time.Time    `json:"timestamp"`
	Kind      EventKind    `json:"kind"`
	Pod       string       `json:"pod"`
	Peer      *cilium.Peer `json:"peer,omitempty"`
	Message   string       `json:"message,omitempty"`
}
