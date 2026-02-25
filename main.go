package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	flag "github.com/spf13/pflag"
	"k8s.io/klog/v2"

	"github.com/aurelcanciu/ocellus/internal/cilium"
	"github.com/aurelcanciu/ocellus/internal/k8s"
	"github.com/aurelcanciu/ocellus/internal/tui"
)

var version = "dev"

func main() {
	// Silence klog to prevent client-go log messages from corrupting the TUI.
	klog.SetOutput(io.Discard)

	showVersion := flag.Bool("version", false, "Print version and exit")
	namespace := flag.StringP("namespace", "n", "default", "Kubernetes namespace")
	port := flag.StringP("port", "p", "", "TCP port or range to track (e.g. 5432, 5432-5440)")
	proto := flag.String("proto", "tcp", "Protocol filter: tcp, udp, or tcp,udp")
	src := flag.String("src", "", "Source IP or CIDR filter (e.g. 10.4.166.0/24)")
	state := flag.String("state", "established", "Connection state: established, closing, all")
	interval := flag.IntP("interval", "i", 10, "Polling interval in seconds")
	timeout := flag.Int("timeout", 0, "Poll timeout in seconds (0 = no timeout)")
	kubeconfig := flag.String("kubeconfig", "", "Path to kubeconfig (default: standard resolution)")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: ocellus [flags] <target>\n\n")
		fmt.Fprintf(os.Stderr, "Target formats:\n")
		fmt.Fprintf(os.Stderr, "  deployment/name  deploy/name  statefulset/name  sts/name\n")
		fmt.Fprintf(os.Stderr, "  daemonset/name   ds/name      replicaset/name   rs/name   pod-name\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	if *showVersion {
		fmt.Println("ocellus", version)
		os.Exit(0)
	}

	args := flag.Args()
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "error: exactly one target argument required")
		flag.Usage()
		os.Exit(1)
	}

	// Build filter.
	filter, err := cilium.NewFilter(cilium.FilterOpts{
		Port:  *port,
		Proto: *proto,
		Src:   *src,
		State: *state,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
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

	ctx := context.Background()
	pods, err := k8s.DiscoverPods(ctx, client, *namespace, target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	m := tui.New(tui.Config{
		Filter:      filter,
		Namespace:   *namespace,
		Target:      target,
		Interval:    time.Duration(*interval) * time.Second,
		PollTimeout: time.Duration(*timeout) * time.Second,
		Client:      client,
		Source:      cilium.NewAutoSource(),
		Pods:        pods,
	})

	p := tea.NewProgram(m, tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
