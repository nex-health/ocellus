package poll

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/nex-health/ocellus/internal/capture"
	"github.com/nex-health/ocellus/internal/cilium"
	"github.com/nex-health/ocellus/internal/k8s"
)

// Params holds the parameters for a single poll cycle.
type Params struct {
	Client  cilium.PodExecer
	Source  cilium.ConntrackSource
	Filter  cilium.Filter
	Pods    []k8s.PodInfo
	Exited  map[string]bool // pods to skip (already known exited)
	Timeout time.Duration   // per-node timeout; 0 = no timeout
}

// Once polls all nodes for conntrack data and returns a snapshot.
// It groups pods by node, fans out one goroutine per node, finds the
// Cilium agent, queries conntrack peers, and maps results back to pod names.
func Once(ctx context.Context, p Params) capture.Snapshot {
	if p.Source == nil {
		p.Source = &cilium.TextSource{}
	}

	// Group active pods by node.
	nodeGroups := make(map[string][]k8s.PodInfo)
	for _, pod := range p.Pods {
		if !p.Exited[pod.Name] {
			nodeGroups[pod.Node] = append(nodeGroups[pod.Node], pod)
		}
	}

	var mu sync.Mutex
	peerResults := make(map[string][]cilium.Peer)
	var pollErrors []string

	var wg sync.WaitGroup
	for node, nodePods := range nodeGroups {
		wg.Add(1)
		go func(node string, nodePods []k8s.PodInfo) {
			defer wg.Done()
			nodeCtx := ctx
			if p.Timeout > 0 {
				var cancel context.CancelFunc
				nodeCtx, cancel = context.WithTimeout(ctx, p.Timeout)
				defer cancel()
			}
			agentName, err := cilium.FindCiliumAgent(nodeCtx, p.Client, node)
			if err != nil {
				mu.Lock()
				pollErrors = append(pollErrors, fmt.Sprintf("node %s: %v", node, err))
				mu.Unlock()
				return
			}
			podIPs := make([]string, len(nodePods))
			for i, pod := range nodePods {
				podIPs[i] = pod.IP
			}
			results, err := p.Source.QueryPeers(nodeCtx, p.Client, agentName, podIPs, p.Filter)
			if err != nil {
				mu.Lock()
				pollErrors = append(pollErrors, fmt.Sprintf("node %s: %v", node, err))
				mu.Unlock()
				return
			}
			mu.Lock()
			for _, pod := range nodePods {
				if peers, ok := results[pod.IP]; ok {
					peerResults[pod.Name] = peers
				}
			}
			mu.Unlock()
		}(node, nodePods)
	}
	wg.Wait()

	return capture.Snapshot{
		Timestamp: time.Now().UTC(),
		Pods:      peerResults,
		Errors:    pollErrors,
	}
}
