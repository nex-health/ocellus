package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	flag "github.com/spf13/pflag"
	"k8s.io/klog/v2"

	"github.com/nex-health/ocellus/internal/capture"
	"github.com/nex-health/ocellus/internal/cilium"
	"github.com/nex-health/ocellus/internal/k8s"
	"github.com/nex-health/ocellus/internal/poll"
	"github.com/nex-health/ocellus/internal/tui"
)

var version = "dev"

func main() {
	// Silence klog to prevent client-go log messages from corrupting the TUI.
	klog.SetOutput(io.Discard)

	showVersion := flag.Bool("version", false, "Print version and exit")
	namespace := flag.StringP("namespace", "n", "default", "Kubernetes namespace")
	port := flag.StringP("port", "p", "", "TCP port or range to track (e.g. 5432, 5432-5440)")
	proto := flag.String("proto", "tcp,udp", "Protocol filter: tcp, udp, or tcp,udp")
	src := flag.String("src", "", "Source IP or CIDR filter (e.g. 10.4.166.0/24)")
	state := flag.String("state", "all", "Connection state: established, closing, all")
	direction := flag.String("direction", "all", "Connection direction: in, out, all")
	interval := flag.IntP("interval", "i", 10, "Polling interval in seconds")
	timeout := flag.Int("timeout", 0, "Poll timeout in seconds (0 = no timeout)")
	kubeconfig := flag.String("kubeconfig", "", "Path to kubeconfig (default: standard resolution)")
	outputFormat := flag.StringP("output-format", "o", "jsonl", "Capture format: jsonl, json, csv, text")
	outputFile := flag.StringP("output-file", "f", "", "Capture output file (default: auto-generated)")
	ipVersion := flag.String("ip-version", "all", "IP version: 4, 6, all")
	dump := flag.Bool("dump", false, "Non-interactive dump mode (bypasses TUI)")
	repeat := flag.Int("repeat", 0, "Repeat interval in seconds for dump mode (0 = one-shot)")
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
		Port:      *port,
		Proto:     *proto,
		Src:       *src,
		State:     *state,
		Direction: *direction,
		IPVersion: *ipVersion,
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

	if err := cilium.CheckInstalled(ctx, client); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	pods, err := k8s.DiscoverPods(ctx, client, *namespace, target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	if *dump {
		if err := runDumpMode(client, cilium.NewAutoSource(), filter, pods, *outputFormat, *outputFile, *repeat, *timeout); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	// Redirect stderr to suppress exec-based kubeconfig plugin output
	// (e.g. aws-iam-authenticator, gke-gcloud-auth-plugin) that would
	// corrupt the Bubble Tea alt-screen.
	origStderr := os.Stderr
	devNull, devNullErr := os.Open(os.DevNull)
	if devNullErr == nil {
		os.Stderr = devNull
	}

	m := tui.New(tui.Config{
		Filter:       filter,
		Namespace:    *namespace,
		Context:      client.Context(),
		Target:       target,
		Interval:     time.Duration(*interval) * time.Second,
		PollTimeout:  time.Duration(*timeout) * time.Second,
		Client:       client,
		Source:       cilium.NewAutoSource(),
		Pods:         pods,
		OutputFormat: *outputFormat,
		OutputFile:   *outputFile,
	})

	p := tea.NewProgram(m, tea.WithAltScreen())
	finalModel, err := p.Run()

	// Restore stderr before any post-TUI output.
	os.Stderr = origStderr
	if devNullErr == nil {
		devNull.Close()
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	if fm, ok := finalModel.(tui.Model); ok {
		fm.CloseRecorder()
		if path := fm.CaptureFilePath(); path != "" {
			fmt.Fprintf(os.Stderr, "Capture written to %s\n", path)
		}
	}
}

func runDumpMode(client tui.ClusterClient, source cilium.ConntrackSource, filter cilium.Filter, pods []k8s.PodInfo, format, outputFile string, repeatSec, timeoutSec int) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	f, err := capture.NewFormatter(format)
	if err != nil {
		return err
	}

	var w capture.Writer
	var closer func()
	if outputFile != "" {
		fw, err := capture.NewFileWriter(outputFile)
		if err != nil {
			return err
		}
		w = fw
		closer = func() { fw.Close() }
	} else {
		w = capture.NewStreamWriter(os.Stdout)
	}
	defer func() {
		if closer != nil {
			closer()
		}
	}()

	pollParams := poll.Params{
		Client:  client,
		Source:  source,
		Filter:  filter,
		Pods:    pods,
		Timeout: time.Duration(timeoutSec) * time.Second,
	}

	snap := poll.Once(ctx, pollParams)
	if err := capture.DumpOnce(f, w, snap); err != nil {
		return err
	}
	if repeatSec <= 0 {
		return nil
	}

	ticker := time.NewTicker(time.Duration(repeatSec) * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			snap := poll.Once(ctx, pollParams)
			if err := capture.DumpOnce(f, w, snap); err != nil {
				return err
			}
		}
	}
}
