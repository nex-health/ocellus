package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/aurelcanciu/ocellus/internal/cilium"
	"github.com/aurelcanciu/ocellus/internal/display"
	"github.com/aurelcanciu/ocellus/internal/k8s"
	"golang.org/x/term"
)

func main() {
	namespace := flag.String("n", "default", "Kubernetes namespace")
	port := flag.Int("p", 0, "TCP port to track (required)")
	interval := flag.Int("i", 10, "Polling interval in seconds")
	kubeconfig := flag.String("kubeconfig", "", "Path to kubeconfig (default: standard resolution)")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: ocellus [flags] <target>\n\n")
		fmt.Fprintf(os.Stderr, "Target formats:\n")
		fmt.Fprintf(os.Stderr, "  deployment/name    statefulset/name    daemonset/name    pod-name\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	if *port == 0 {
		fmt.Fprintln(os.Stderr, "error: -p (port) is required")
		flag.Usage()
		os.Exit(1)
	}

	args := flag.Args()
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "error: exactly one target argument required")
		flag.Usage()
		os.Exit(1)
	}

	target, err := k8s.ParseTarget(args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	client, err := k8s.NewClient(*kubeconfig)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		cancel()
	}()

	pods, err := k8s.DiscoverPods(ctx, client, *namespace, target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "\033[1mTracking %d pod(s)\033[0m \033[2m(every %ds, Ctrl+C to stop and write report)\033[0m\n", len(pods), *interval)
	for _, p := range pods {
		fmt.Fprintf(os.Stderr, "  %s\n", p.Name)
	}

	exited := make(map[string]bool)
	lastPeers := make(map[string][]string)

	for {
		nodeGroups := make(map[string][]k8s.PodInfo)
		for _, p := range pods {
			if !exited[p.Name] {
				nodeGroups[p.Node] = append(nodeGroups[p.Node], p)
			}
		}

		activePods := 0
		for _, p := range pods {
			if !exited[p.Name] {
				activePods++
			}
		}

		if activePods == 0 {
			break
		}

		var mu sync.Mutex
		peerResults := make(map[string][]string)
		var wg sync.WaitGroup

		for node, nodePods := range nodeGroups {
			wg.Add(1)
			go func(node string, nodePods []k8s.PodInfo) {
				defer wg.Done()
				agentName, err := cilium.FindCiliumAgent(ctx, client, node)
				if err != nil {
					fmt.Fprintf(os.Stderr, "WARNING: %v\n", err)
					return
				}
				ctOutput, err := cilium.QueryNode(ctx, client, agentName)
				if err != nil {
					fmt.Fprintf(os.Stderr, "WARNING: %v\n", err)
					return
				}
				mu.Lock()
				defer mu.Unlock()
				for _, p := range nodePods {
					peers := cilium.ParseCTOutput(ctOutput, p.IP, *port)
					peerResults[p.Name] = peers
				}
			}(node, nodePods)
		}
		wg.Wait()

		if ctx.Err() != nil {
			break
		}

		for name, peers := range peerResults {
			lastPeers[name] = peers
		}

		currentPods, err := k8s.DiscoverPods(ctx, client, *namespace, target)
		if err == nil {
			currentNames := make(map[string]bool)
			for _, p := range currentPods {
				currentNames[p.Name] = true
			}
			for _, p := range pods {
				if !exited[p.Name] && !currentNames[p.Name] {
					exited[p.Name] = true
				}
			}
		}

		statuses := buildStatuses(pods, exited, lastPeers)
		width := termWidth()
		display.RenderCycle(os.Stdout, statuses, *port, time.Now().UTC(), width)

		select {
		case <-ctx.Done():
			goto done
		case <-time.After(time.Duration(*interval) * time.Second):
		}
	}

done:
	statuses := buildStatuses(pods, exited, lastPeers)
	reportFile := fmt.Sprintf("ocellus-report-%s.txt", time.Now().UTC().Format("20060102T150405Z"))
	f, err := os.Create(reportFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error writing report: %v\n", err)
		os.Exit(1)
	}
	display.WriteReport(f, statuses, *port, time.Now().UTC())
	f.Close()
	fmt.Fprintf(os.Stderr, "\n\033[0;32mReport written to \033[1m%s\033[0m\n", reportFile)
}

func buildStatuses(pods []k8s.PodInfo, exited map[string]bool, lastPeers map[string][]string) []display.PodStatus {
	statuses := make([]display.PodStatus, len(pods))
	for i, p := range pods {
		statuses[i] = display.PodStatus{
			Name:   p.Name,
			Active: !exited[p.Name],
			Peers:  lastPeers[p.Name],
		}
	}
	return statuses
}

func termWidth() int {
	w, _, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil || w <= 0 {
		return 80
	}
	return w
}
