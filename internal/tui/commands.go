package tui

import (
	"context"
	"fmt"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/aurelcanciu/ocellus/internal/cilium"
	"github.com/aurelcanciu/ocellus/internal/k8s"
	"github.com/aurelcanciu/ocellus/internal/poll"
)

// ClusterClient combines the interfaces needed for polling.
type ClusterClient interface {
	k8s.KubeClient
	Exec(ctx context.Context, namespace, pod, container string, cmd []string) (string, error)
}

func pollCmd(client ClusterClient, source cilium.ConntrackSource, namespace string, target k8s.Target, filter cilium.Filter, pods []k8s.PodInfo, exited map[string]bool, timeout time.Duration) tea.Cmd {
	if source == nil {
		source = &cilium.TextSource{}
	}
	return func() tea.Msg {
		ctx := context.Background()

		snap := poll.Once(ctx, poll.Params{
			Client:  client,
			Source:  source,
			Filter:  filter,
			Pods:    pods,
			Exited:  exited,
			Timeout: timeout,
		})

		// Check for exited pods.
		newExited := make(map[string]bool)
		currentPods, err := k8s.DiscoverPods(ctx, client, namespace, target)
		if err != nil {
			snap.Errors = append(snap.Errors, fmt.Sprintf("pod discovery: %v", err))
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
			peers:     snap.Pods,
			exited:    newExited,
			timestamp: snap.Timestamp,
			errors:    snap.Errors,
		}
	}
}

func tickAfter(d time.Duration) tea.Cmd {
	return tea.Tick(d, func(_ time.Time) tea.Msg {
		return tickMsg{}
	})
}

func pendingKeyTimeout() tea.Cmd {
	return tea.Tick(500*time.Millisecond, func(_ time.Time) tea.Msg {
		return pendingKeyTimeoutMsg{}
	})
}
