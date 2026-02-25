package k8s

import (
	"context"
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type PodInfo struct {
	Name string
	Node string
	IP   string
}

type KubeClient interface {
	ListPods(ctx context.Context, namespace string, opts metav1.ListOptions) (*corev1.PodList, error)
	ListReplicaSets(ctx context.Context, namespace string, opts metav1.ListOptions) (*appsv1.ReplicaSetList, error)
	GetPod(ctx context.Context, namespace, name string) (*corev1.Pod, error)
}

func DiscoverPods(ctx context.Context, client KubeClient, namespace string, target Target) ([]PodInfo, error) {
	switch target.Kind {
	case "pod":
		return discoverSinglePod(ctx, client, namespace, target.Name)
	case "deployment":
		return discoverDeploymentPods(ctx, client, namespace, target.Name)
	case "replicaset", "statefulset", "daemonset":
		return discoverOwnedPods(ctx, client, namespace, target.Kind, target.Name)
	default:
		return nil, fmt.Errorf("unsupported kind: %s", target.Kind)
	}
}

func discoverSinglePod(ctx context.Context, client KubeClient, namespace, name string) ([]PodInfo, error) {
	pod, err := client.GetPod(ctx, namespace, name)
	if err != nil {
		return nil, fmt.Errorf("get pod %s: %w", name, err)
	}
	if pod.Status.Phase != corev1.PodRunning {
		return nil, fmt.Errorf("pod %s is not running (phase: %s)", name, pod.Status.Phase)
	}
	return []PodInfo{{Name: pod.Name, Node: pod.Spec.NodeName, IP: pod.Status.PodIP}}, nil
}

func discoverDeploymentPods(ctx context.Context, client KubeClient, namespace, deployName string) ([]PodInfo, error) {
	rsList, err := client.ListReplicaSets(ctx, namespace, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list replicasets: %w", err)
	}

	var rsNames []string
	for _, rs := range rsList.Items {
		for _, ref := range rs.OwnerReferences {
			if ref.Kind == "Deployment" && ref.Name == deployName {
				rsNames = append(rsNames, rs.Name)
			}
		}
	}
	if len(rsNames) == 0 {
		return nil, fmt.Errorf("no replicasets found for deployment %s", deployName)
	}

	return listRunningPodsOwnedBy(ctx, client, namespace, "ReplicaSet", rsNames)
}

func discoverOwnedPods(ctx context.Context, client KubeClient, namespace, kind, name string) ([]PodInfo, error) {
	ownerKind := kindToOwnerKind(kind)
	return listRunningPodsOwnedBy(ctx, client, namespace, ownerKind, []string{name})
}

func listRunningPodsOwnedBy(ctx context.Context, client KubeClient, namespace, ownerKind string, ownerNames []string) ([]PodInfo, error) {
	podList, err := client.ListPods(ctx, namespace, metav1.ListOptions{
		FieldSelector: "status.phase=Running",
	})
	if err != nil {
		return nil, fmt.Errorf("list pods: %w", err)
	}

	nameSet := make(map[string]bool, len(ownerNames))
	for _, n := range ownerNames {
		nameSet[n] = true
	}

	var pods []PodInfo
	for _, pod := range podList.Items {
		for _, ref := range pod.OwnerReferences {
			if ref.Kind == ownerKind && nameSet[ref.Name] {
				pods = append(pods, PodInfo{
					Name: pod.Name,
					Node: pod.Spec.NodeName,
					IP:   pod.Status.PodIP,
				})
				break
			}
		}
	}
	if len(pods) == 0 {
		return nil, fmt.Errorf("no running pods found for %s %s", ownerKind, ownerNames)
	}
	return pods, nil
}

func kindToOwnerKind(kind string) string {
	switch kind {
	case "replicaset":
		return "ReplicaSet"
	case "statefulset":
		return "StatefulSet"
	case "daemonset":
		return "DaemonSet"
	default:
		return kind
	}
}
