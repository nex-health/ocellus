package poll

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/nex-health/ocellus/internal/cilium"
	"github.com/nex-health/ocellus/internal/k8s"
)

type mockClient struct {
	pods       *corev1.PodList
	listPodsFn func(ctx context.Context, namespace string, opts metav1.ListOptions) (*corev1.PodList, error)
	execFn     func(namespace, pod, container string, cmd []string) (string, error)
}

func (m *mockClient) ListPods(ctx context.Context, namespace string, opts metav1.ListOptions) (*corev1.PodList, error) {
	if m.listPodsFn != nil {
		return m.listPodsFn(ctx, namespace, opts)
	}
	if m.pods == nil {
		return &corev1.PodList{}, nil
	}
	return m.pods, nil
}

func (m *mockClient) Exec(_ context.Context, namespace, pod, container string, cmd []string) (string, error) {
	if m.execFn != nil {
		return m.execFn(namespace, pod, container, cmd)
	}
	return "", fmt.Errorf("exec not configured")
}

const sampleCTOutput = `TCP IN 10.4.166.193:52628 -> 10.4.34.6:4143 expires=277365 Packets=5 Bytes=452 RxFlagsSeen=0x02 LastRxReport=277355 TxFlagsSeen=0x12 LastTxReport=277355 Flags=0x0012 [ SeenNonSyn ] RevNAT=0 SourceSecurityID=2 BackendID=0
`

func TestOnce(t *testing.T) {
	client := &mockClient{
		pods: &corev1.PodList{
			Items: []corev1.Pod{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "cilium-agent-1"},
					Status:     corev1.PodStatus{Phase: corev1.PodRunning},
				},
			},
		},
		execFn: func(_, _, _ string, _ []string) (string, error) {
			return sampleCTOutput, nil
		},
	}

	pods := []k8s.PodInfo{
		{Name: "pod-1", Node: "node-a", IP: "10.4.34.6"},
	}

	snap := Once(context.Background(), Params{
		Client:  client,
		Source:  &cilium.TextSource{},
		Filter:  cilium.Filter{PortMin: 4143, PortMax: 4143},
		Pods:    pods,
		Timeout: 0,
	})

	if snap.Timestamp.IsZero() {
		t.Error("Timestamp should be set")
	}
	if len(snap.Pods["pod-1"]) != 1 {
		t.Errorf("pod-1 peers = %d, want 1", len(snap.Pods["pod-1"]))
	}
	if len(snap.Errors) != 0 {
		t.Errorf("errors = %v, want none", snap.Errors)
	}
}

func TestOnceWithErrors(t *testing.T) {
	client := &mockClient{
		execFn: func(_, _, _ string, _ []string) (string, error) {
			return "", fmt.Errorf("connection refused")
		},
	}

	pods := []k8s.PodInfo{
		{Name: "pod-1", Node: "node-a", IP: "10.4.34.6"},
	}

	snap := Once(context.Background(), Params{
		Client:  client,
		Source:  &cilium.TextSource{},
		Filter:  cilium.Filter{PortMin: 4143, PortMax: 4143},
		Pods:    pods,
		Timeout: 0,
	})

	if len(snap.Errors) == 0 {
		t.Error("expected errors when cilium agent not found")
	}
}

func TestOnceSkipsExitedPods(t *testing.T) {
	client := &mockClient{
		pods: &corev1.PodList{
			Items: []corev1.Pod{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "cilium-agent-1"},
					Status:     corev1.PodStatus{Phase: corev1.PodRunning},
				},
			},
		},
		execFn: func(_, _, _ string, _ []string) (string, error) {
			return sampleCTOutput, nil
		},
	}

	pods := []k8s.PodInfo{
		{Name: "pod-1", Node: "node-a", IP: "10.4.34.6"},
		{Name: "pod-2", Node: "node-b", IP: "10.4.34.7"},
	}

	snap := Once(context.Background(), Params{
		Client:  client,
		Source:  &cilium.TextSource{},
		Filter:  cilium.Filter{PortMin: 4143, PortMax: 4143},
		Pods:    pods,
		Exited:  map[string]bool{"pod-2": true},
		Timeout: 0,
	})

	// pod-2 is exited, so only pod-1 should have results.
	if _, ok := snap.Pods["pod-1"]; !ok {
		t.Error("pod-1 should have peers")
	}
}

func TestOnceWithTimeout(t *testing.T) {
	client := &mockClient{
		listPodsFn: func(ctx context.Context, _ string, _ metav1.ListOptions) (*corev1.PodList, error) {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(5 * time.Second):
				return &corev1.PodList{}, nil
			}
		},
		execFn: func(_, _, _ string, _ []string) (string, error) {
			time.Sleep(5 * time.Second)
			return "", fmt.Errorf("should not reach")
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	pods := []k8s.PodInfo{
		{Name: "pod-1", Node: "node-a", IP: "10.4.34.6"},
	}

	snap := Once(ctx, Params{
		Client:  client,
		Source:  &cilium.TextSource{},
		Filter:  cilium.Filter{PortMin: 4143, PortMax: 4143},
		Pods:    pods,
		Timeout: 50 * time.Millisecond,
	})

	if len(snap.Errors) == 0 {
		t.Error("expected timeout errors")
	}
	hasTimeout := false
	for _, e := range snap.Errors {
		if strings.Contains(e, "context") {
			hasTimeout = true
		}
	}
	if !hasTimeout {
		t.Errorf("expected context timeout error, got: %v", snap.Errors)
	}
}
