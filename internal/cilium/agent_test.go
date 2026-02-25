package cilium

import (
	"context"
	"fmt"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type mockPodExecer struct {
	pods   *corev1.PodList
	execFn func(namespace, pod, container string, cmd []string) (string, error)
}

func (m *mockPodExecer) ListPods(_ context.Context, _ string, _ metav1.ListOptions) (*corev1.PodList, error) {
	if m.pods == nil {
		return &corev1.PodList{}, nil
	}
	return m.pods, nil
}

func (m *mockPodExecer) Exec(_ context.Context, namespace, pod, container string, cmd []string) (string, error) {
	if m.execFn != nil {
		return m.execFn(namespace, pod, container, cmd)
	}
	return "", fmt.Errorf("exec not configured")
}

func TestFindCiliumAgent(t *testing.T) {
	client := &mockPodExecer{
		pods: &corev1.PodList{
			Items: []corev1.Pod{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "cilium-abc"},
					Status:     corev1.PodStatus{Phase: corev1.PodRunning},
				},
			},
		},
	}

	name, err := FindCiliumAgent(context.Background(), client, "node-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if name != "cilium-abc" {
		t.Errorf("expected cilium-abc, got %s", name)
	}
}

func TestFindCiliumAgent_NoneFound(t *testing.T) {
	client := &mockPodExecer{
		pods: &corev1.PodList{},
	}

	_, err := FindCiliumAgent(context.Background(), client, "node-1")
	if err == nil {
		t.Fatal("expected error when no agent found")
	}
}

func TestQueryNode(t *testing.T) {
	client := &mockPodExecer{
		execFn: func(_, pod, container string, _ []string) (string, error) {
			if pod == "cilium-abc" && container == "cilium-agent" {
				return "TCP IN 10.0.0.1:1234 -> 10.0.0.2:5432 ...\n", nil
			}
			return "", fmt.Errorf("unexpected call")
		},
	}

	output, err := QueryNode(context.Background(), client, "cilium-abc")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if output == "" {
		t.Error("expected non-empty output")
	}
}
