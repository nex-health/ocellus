package capture

import (
	"fmt"
	"sort"

	"github.com/nex-health/ocellus/internal/cilium"
)

// Diff compares two snapshots and returns events describing changes.
// If prev is nil, this is treated as the first snapshot.
func Diff(prev *Snapshot, curr Snapshot) []Event {
	var events []Event

	// Pod-level events.
	prevPodNames := make(map[string]bool)
	if prev != nil {
		for name := range prev.Pods {
			prevPodNames[name] = true
		}
	}

	// Sort pod names for deterministic ordering.
	podNames := make([]string, 0, len(curr.Pods))
	for name := range curr.Pods {
		podNames = append(podNames, name)
	}
	sort.Strings(podNames)

	for _, podName := range podNames {
		if !prevPodNames[podName] {
			events = append(events, Event{
				Timestamp: curr.Timestamp,
				Kind:      EventPodDiscovered,
				Pod:       podName,
			})
		}
	}

	// Pod exited events.
	prevExited := make(map[string]bool)
	if prev != nil {
		prevExited = prev.Exited
	}
	exitedNames := make([]string, 0, len(curr.Exited))
	for name := range curr.Exited {
		exitedNames = append(exitedNames, name)
	}
	sort.Strings(exitedNames)
	for _, name := range exitedNames {
		if !prevExited[name] {
			events = append(events, Event{
				Timestamp: curr.Timestamp,
				Kind:      EventPodExited,
				Pod:       name,
			})
		}
	}

	// Peer-level events (only if we have a previous snapshot).
	if prev != nil {
		for _, podName := range podNames {
			currPeers := curr.Pods[podName]
			prevPeers := prev.Pods[podName]

			currSet := makePeerSet(currPeers)
			prevSet := makePeerSet(prevPeers)

			// Added peers.
			for src, peer := range currSet {
				if _, ok := prevSet[src]; !ok {
					p := peer
					events = append(events, Event{
						Timestamp: curr.Timestamp,
						Kind:      EventPeerAdded,
						Pod:       podName,
						Peer:      &p,
					})
				}
			}

			// Removed peers.
			for src, peer := range prevSet {
				if _, ok := currSet[src]; !ok {
					p := peer
					events = append(events, Event{
						Timestamp: curr.Timestamp,
						Kind:      EventPeerRemoved,
						Pod:       podName,
						Peer:      &p,
					})
				}
			}

			// Traffic spikes (2x threshold).
			for src, currPeer := range currSet {
				if prevPeer, ok := prevSet[src]; ok {
					if prevPeer.Bytes > 0 && currPeer.Bytes > prevPeer.Bytes*2 {
						p := currPeer
						events = append(events, Event{
							Timestamp: curr.Timestamp,
							Kind:      EventTrafficSpike,
							Pod:       podName,
							Peer:      &p,
							Message: fmt.Sprintf("bytes %d -> %d (%.1fx)",
								prevPeer.Bytes, currPeer.Bytes,
								float64(currPeer.Bytes)/float64(prevPeer.Bytes)),
						})
					}
				}
			}
		}
	}

	// Poll error events.
	prevErrors := make(map[string]bool)
	if prev != nil {
		for _, e := range prev.Errors {
			prevErrors[e] = true
		}
	}
	for _, e := range curr.Errors {
		if !prevErrors[e] {
			events = append(events, Event{
				Timestamp: curr.Timestamp,
				Kind:      EventPollError,
				Message:   e,
			})
		}
	}

	return events
}

// makePeerSet creates a map keyed by direction+src for fast lookup.
// Including direction prevents collisions when the same remote address
// appears as both an inbound and outbound peer.
func makePeerSet(peers []cilium.Peer) map[string]cilium.Peer {
	m := make(map[string]cilium.Peer, len(peers))
	for _, p := range peers {
		m[p.Direction+":"+p.Src] = p
	}
	return m
}
