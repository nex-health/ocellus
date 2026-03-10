package tui

import (
	"context"
	"fmt"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/nex-health/ocellus/internal/cilium"
	"github.com/nex-health/ocellus/internal/k8s"
	"github.com/nex-health/ocellus/internal/poll"
)

// ClusterClient combines the interfaces needed for polling.
type ClusterClient interface {
	k8s.KubeClient
	Exec(ctx context.Context, namespace, pod, container string, cmd []string) (string, error)
}

// pollConfig holds the parameters for a poll command.
type pollConfig struct {
	client    ClusterClient
	source    cilium.ConntrackSource
	namespace string
	target    k8s.Target
	filter    cilium.Filter
	pods      []k8s.PodInfo
	exited    map[string]bool
	timeout   time.Duration
}

func pollCmd(cfg pollConfig) tea.Cmd {
	if cfg.source == nil {
		cfg.source = &cilium.TextSource{}
	}
	return func() tea.Msg {
		ctx := context.Background()

		snap := poll.Once(ctx, poll.Params{
			Client:  cfg.client,
			Source:  cfg.source,
			Filter:  cfg.filter,
			Pods:    cfg.pods,
			Exited:  cfg.exited,
			Timeout: cfg.timeout,
		})

		// Check for exited pods.
		newExited := make(map[string]bool)
		currentPods, err := k8s.DiscoverPods(ctx, cfg.client, cfg.namespace, cfg.target)
		if err != nil {
			snap.Errors = append(snap.Errors, fmt.Sprintf("pod discovery: %v", err))
		} else {
			currentNames := make(map[string]bool)
			for _, p := range currentPods {
				currentNames[p.Name] = true
			}
			for _, p := range cfg.pods {
				if !cfg.exited[p.Name] && !currentNames[p.Name] {
					newExited[p.Name] = true
				}
			}
		}

		return pollResultMsg{
			peers:     snap.Pods,
			exited:    newExited,
			pods:      currentPods,
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
