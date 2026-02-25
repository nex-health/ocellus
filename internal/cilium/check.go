package cilium

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// CheckInstalled verifies that Cilium is installed in the cluster by looking
// for running pods with the k8s-app=cilium label in kube-system.
func CheckInstalled(ctx context.Context, client PodExecer) error {
	pods, err := client.ListPods(ctx, "kube-system", metav1.ListOptions{
		LabelSelector: "k8s-app=cilium",
	})
	if err != nil {
		return fmt.Errorf("check cilium installation: %w", err)
	}
	for _, pod := range pods.Items {
		if pod.Status.Phase == corev1.PodRunning {
			return nil
		}
	}
	return fmt.Errorf("cilium not found: no running pods with label k8s-app=cilium in kube-system namespace")
}
