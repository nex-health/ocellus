package cilium

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type PodExecer interface {
	ListPods(ctx context.Context, namespace string, opts metav1.ListOptions) (*corev1.PodList, error)
	Exec(ctx context.Context, namespace, pod, container string, cmd []string) (string, error)
}

// FindCiliumAgent finds the Cilium agent pod running on the given node.
func FindCiliumAgent(ctx context.Context, client PodExecer, node string) (string, error) {
	pods, err := client.ListPods(ctx, "kube-system", metav1.ListOptions{
		LabelSelector: "k8s-app=cilium",
		FieldSelector: "spec.nodeName=" + node,
	})
	if err != nil {
		return "", fmt.Errorf("list cilium pods on node %s: %w", node, err)
	}
	for _, pod := range pods.Items {
		if pod.Status.Phase == corev1.PodRunning {
			return pod.Name, nil
		}
	}
	return "", fmt.Errorf("no running Cilium agent on node %s", node)
}

// QueryNode execs into the Cilium agent on a node and returns the raw CT output.
func QueryNode(ctx context.Context, client PodExecer, ciliumPod string) (string, error) {
	output, err := client.Exec(ctx, "kube-system", ciliumPod, "cilium-agent", []string{
		"cilium", "bpf", "ct", "list", "global",
	})
	if err != nil {
		return "", fmt.Errorf("exec into %s: %w", ciliumPod, err)
	}
	return output, nil
}
