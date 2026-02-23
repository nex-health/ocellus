package k8s

import (
	"context"
	"fmt"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type mockKubeClient struct {
	pods        *corev1.PodList
	replicaSets *appsv1.ReplicaSetList
	getPodFn    func(namespace, name string) (*corev1.Pod, error)
}

func (m *mockKubeClient) ListPods(_ context.Context, _ string, _ metav1.ListOptions) (*corev1.PodList, error) {
	if m.pods == nil {
		return &corev1.PodList{}, nil
	}
	return m.pods, nil
}

func (m *mockKubeClient) ListReplicaSets(_ context.Context, _ string, _ metav1.ListOptions) (*appsv1.ReplicaSetList, error) {
	if m.replicaSets == nil {
		return &appsv1.ReplicaSetList{}, nil
	}
	return m.replicaSets, nil
}

func (m *mockKubeClient) GetPod(_ context.Context, namespace, name string) (*corev1.Pod, error) {
	if m.getPodFn != nil {
		return m.getPodFn(namespace, name)
	}
	return nil, fmt.Errorf("pod %s not found", name)
}

func TestDiscoverPods_SinglePod(t *testing.T) {
	client := &mockKubeClient{
		getPodFn: func(_, name string) (*corev1.Pod, error) {
			return &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: name},
				Spec:       corev1.PodSpec{NodeName: "node-1"},
				Status:     corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "10.0.0.1"},
			}, nil
		},
	}

	pods, err := DiscoverPods(context.Background(), client, "default", Target{Kind: "pod", Name: "my-pod"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pods) != 1 {
		t.Fatalf("expected 1 pod, got %d", len(pods))
	}
	if pods[0].Name != "my-pod" || pods[0].Node != "node-1" || pods[0].IP != "10.0.0.1" {
		t.Errorf("unexpected pod info: %+v", pods[0])
	}
}

func TestDiscoverPods_SinglePodNotRunning(t *testing.T) {
	client := &mockKubeClient{
		getPodFn: func(_, name string) (*corev1.Pod, error) {
			return &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: name},
				Status:     corev1.PodStatus{Phase: corev1.PodPending},
			}, nil
		},
	}

	_, err := DiscoverPods(context.Background(), client, "default", Target{Kind: "pod", Name: "my-pod"})
	if err == nil {
		t.Fatal("expected error for non-running pod")
	}
}

func TestDiscoverPods_Deployment(t *testing.T) {
	client := &mockKubeClient{
		replicaSets: &appsv1.ReplicaSetList{
			Items: []appsv1.ReplicaSet{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "pgbouncer-abc123",
						OwnerReferences: []metav1.OwnerReference{{Kind: "Deployment", Name: "pgbouncer"}},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "other-rs",
						OwnerReferences: []metav1.OwnerReference{{Kind: "Deployment", Name: "other"}},
					},
				},
			},
		},
		pods: &corev1.PodList{
			Items: []corev1.Pod{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "pgbouncer-abc123-pod1",
						OwnerReferences: []metav1.OwnerReference{{Kind: "ReplicaSet", Name: "pgbouncer-abc123"}},
					},
					Spec:   corev1.PodSpec{NodeName: "node-1"},
					Status: corev1.PodStatus{PodIP: "10.0.0.1"},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "pgbouncer-abc123-pod2",
						OwnerReferences: []metav1.OwnerReference{{Kind: "ReplicaSet", Name: "pgbouncer-abc123"}},
					},
					Spec:   corev1.PodSpec{NodeName: "node-2"},
					Status: corev1.PodStatus{PodIP: "10.0.0.2"},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "other-pod",
						OwnerReferences: []metav1.OwnerReference{{Kind: "ReplicaSet", Name: "other-rs"}},
					},
					Spec:   corev1.PodSpec{NodeName: "node-1"},
					Status: corev1.PodStatus{PodIP: "10.0.0.3"},
				},
			},
		},
	}

	pods, err := DiscoverPods(context.Background(), client, "nexhealth", Target{Kind: "deployment", Name: "pgbouncer"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pods) != 2 {
		t.Fatalf("expected 2 pods, got %d", len(pods))
	}
}

func TestDiscoverPods_StatefulSet(t *testing.T) {
	client := &mockKubeClient{
		pods: &corev1.PodList{
			Items: []corev1.Pod{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "postgres-0",
						OwnerReferences: []metav1.OwnerReference{{Kind: "StatefulSet", Name: "postgres"}},
					},
					Spec:   corev1.PodSpec{NodeName: "node-1"},
					Status: corev1.PodStatus{PodIP: "10.0.0.1"},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "postgres-1",
						OwnerReferences: []metav1.OwnerReference{{Kind: "StatefulSet", Name: "postgres"}},
					},
					Spec:   corev1.PodSpec{NodeName: "node-2"},
					Status: corev1.PodStatus{PodIP: "10.0.0.2"},
				},
			},
		},
	}

	pods, err := DiscoverPods(context.Background(), client, "default", Target{Kind: "statefulset", Name: "postgres"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pods) != 2 {
		t.Fatalf("expected 2 pods, got %d", len(pods))
	}
}

func TestDiscoverPods_DaemonSet(t *testing.T) {
	client := &mockKubeClient{
		pods: &corev1.PodList{
			Items: []corev1.Pod{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "fluentd-abc",
						OwnerReferences: []metav1.OwnerReference{{Kind: "DaemonSet", Name: "fluentd"}},
					},
					Spec:   corev1.PodSpec{NodeName: "node-1"},
					Status: corev1.PodStatus{PodIP: "10.0.0.1"},
				},
			},
		},
	}

	pods, err := DiscoverPods(context.Background(), client, "default", Target{Kind: "daemonset", Name: "fluentd"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pods) != 1 {
		t.Fatalf("expected 1 pod, got %d", len(pods))
	}
}

func TestDiscoverPods_DeploymentNoReplicaSets(t *testing.T) {
	client := &mockKubeClient{
		replicaSets: &appsv1.ReplicaSetList{},
	}

	_, err := DiscoverPods(context.Background(), client, "default", Target{Kind: "deployment", Name: "missing"})
	if err == nil {
		t.Fatal("expected error for missing deployment")
	}
}
