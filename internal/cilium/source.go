package cilium

import "context"

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
