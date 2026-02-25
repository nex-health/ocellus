package cilium

import (
	"context"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestCheckInstalled_NoCilium(t *testing.T) {
	client := &mockPodExecer{}
	err := CheckInstalled(context.Background(), client)
	if err == nil {
		t.Fatal("expected error when no Cilium pods found")
	}
	if !strings.Contains(err.Error(), "cilium not found") {
		t.Errorf("error = %q, want to contain 'cilium not found'", err)
	}
}

func TestCheckInstalled_CiliumPresent(t *testing.T) {
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
	err := CheckInstalled(context.Background(), client)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCheckInstalled_CiliumNotRunning(t *testing.T) {
	client := &mockPodExecer{
		pods: &corev1.PodList{
			Items: []corev1.Pod{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "cilium-abc"},
					Status:     corev1.PodStatus{Phase: corev1.PodPending},
				},
			},
		},
	}
	err := CheckInstalled(context.Background(), client)
	if err == nil {
		t.Fatal("expected error when Cilium pods exist but none are running")
	}
}
