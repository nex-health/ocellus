package tui

import (
	"context"
	"fmt"
	"sync"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/aurelcanciu/ocellus/internal/cilium"
	"github.com/aurelcanciu/ocellus/internal/k8s"
)

// ClusterClient combines the interfaces needed for polling.
type ClusterClient interface {
	k8s.KubeClient
	Exec(ctx context.Context, namespace, pod, container string, cmd []string) (string, error)
}

func pollCmd(client ClusterClient, namespace string, target k8s.Target, filter cilium.Filter, pods []k8s.PodInfo, exited map[string]bool, timeout time.Duration) tea.Cmd {
	return func() tea.Msg {
		ctx := context.Background()

		// Group active pods by node.
		nodeGroups := make(map[string][]k8s.PodInfo)
		for _, p := range pods {
			if !exited[p.Name] {
				nodeGroups[p.Node] = append(nodeGroups[p.Node], p)
			}
		}

		var mu sync.Mutex
		peerResults := make(map[string][]cilium.Peer)
		var pollErrors []string

		addError := func(msg string) {
			mu.Lock()
			pollErrors = append(pollErrors, msg)
			mu.Unlock()
		}

		var wg sync.WaitGroup
		for node, nodePods := range nodeGroups {
			wg.Add(1)
			go func(node string, nodePods []k8s.PodInfo) {
				defer wg.Done()
				nodeCtx := ctx
				if timeout > 0 {
					var cancel context.CancelFunc
					nodeCtx, cancel = context.WithTimeout(ctx, timeout)
					defer cancel()
				}
				agentName, err := cilium.FindCiliumAgent(nodeCtx, client, node)
				if err != nil {
					addError(fmt.Sprintf("node %s: %v", node, err))
					return
				}
				ctOutput, err := cilium.QueryNode(nodeCtx, client, agentName)
				if err != nil {
					addError(fmt.Sprintf("node %s: %v", node, err))
					return
				}
				mu.Lock()
				defer mu.Unlock()
				for _, p := range nodePods {
					peers := cilium.ParseCTOutput(ctOutput, p.IP, filter)
					peerResults[p.Name] = peers
				}
			}(node, nodePods)
		}
		wg.Wait()

		// Check for exited pods.
		newExited := make(map[string]bool)
		currentPods, err := k8s.DiscoverPods(ctx, client, namespace, target)
		if err != nil {
			addError(fmt.Sprintf("pod discovery: %v", err))
		} else {
			currentNames := make(map[string]bool)
			for _, p := range currentPods {
				currentNames[p.Name] = true
			}
			for _, p := range pods {
				if !exited[p.Name] && !currentNames[p.Name] {
					newExited[p.Name] = true
				}
			}
		}

		return pollResultMsg{
			peers:     peerResults,
			exited:    newExited,
			timestamp: time.Now().UTC(),
			errors:    pollErrors,
		}
	}
}

func tickAfter(d time.Duration) tea.Cmd {
	return tea.Tick(d, func(t time.Time) tea.Msg {
		return tickMsg{}
	})
}

func pendingKeyTimeout() tea.Cmd {
	return tea.Tick(500*time.Millisecond, func(t time.Time) tea.Msg {
		return pendingKeyTimeoutMsg{}
	})
}
