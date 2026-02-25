package cilium

import (
	"context"
	"sync"
)

// ConntrackSource abstracts how conntrack data is retrieved from a node.
type ConntrackSource interface {
	QueryPeers(ctx context.Context, client PodExecer, ciliumPod string, podIPs []string, filter Filter) (map[string][]Peer, error)
}

// TextSource queries conntrack using the text CLI output (current behavior).
type TextSource struct{}

func (s *TextSource) QueryPeers(ctx context.Context, client PodExecer, ciliumPod string, podIPs []string, filter Filter) (map[string][]Peer, error) {
	output, err := QueryNode(ctx, client, ciliumPod)
	if err != nil {
		return nil, err
	}
	results := make(map[string][]Peer, len(podIPs))
	for _, ip := range podIPs {
		results[ip] = ParseCTOutput(output, ip, filter)
	}
	return results, nil
}

// AutoSource tries JSON first, falls back to text.
// Once a method succeeds, it remembers the choice for subsequent calls.
type AutoSource struct {
	mu        sync.Mutex
	preferred string // "json", "text", or "" (unknown)
}

func NewAutoSource() *AutoSource {
	return &AutoSource{}
}

func (s *AutoSource) QueryPeers(ctx context.Context, client PodExecer, ciliumPod string, podIPs []string, filter Filter) (map[string][]Peer, error) {
	s.mu.Lock()
	pref := s.preferred
	s.mu.Unlock()

	if pref == "text" {
		return (&TextSource{}).QueryPeers(ctx, client, ciliumPod, podIPs, filter)
	}

	// Try JSON.
	results, err := (&JSONSource{}).QueryPeers(ctx, client, ciliumPod, podIPs, filter)
	if err == nil {
		// Verify JSON actually produced results. If it parsed successfully
		// but returned zero peers, the JSON format likely doesn't match our
		// structs (field names, encoding, etc.) — fall back to text.
		total := 0
		for _, peers := range results {
			total += len(peers)
		}
		if total > 0 {
			s.mu.Lock()
			s.preferred = "json"
			s.mu.Unlock()
			return results, nil
		}
	}

	// Fall back to text.
	results, err = (&TextSource{}).QueryPeers(ctx, client, ciliumPod, podIPs, filter)
	if err == nil {
		s.mu.Lock()
		s.preferred = "text"
		s.mu.Unlock()
	}
	return results, err
}
