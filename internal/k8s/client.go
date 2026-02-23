package k8s

import (
	"bytes"
	"context"
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/remotecommand"
)

// Client wraps a real Kubernetes clientset and implements both KubeClient and
// cilium.PodExecer interfaces.
type Client struct {
	clientset  kubernetes.Interface
	restConfig *rest.Config
}

func NewClient(kubeconfig string) (*Client, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	if kubeconfig != "" {
		rules.ExplicitPath = kubeconfig
	}

	config, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		rules, &clientcmd.ConfigOverrides{},
	).ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("load kubeconfig: %w", err)
	}

	cs, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("create kubernetes client: %w", err)
	}

	return &Client{clientset: cs, restConfig: config}, nil
}

func (c *Client) ListPods(ctx context.Context, namespace string, opts metav1.ListOptions) (*corev1.PodList, error) {
	return c.clientset.CoreV1().Pods(namespace).List(ctx, opts)
}

func (c *Client) ListReplicaSets(ctx context.Context, namespace string, opts metav1.ListOptions) (*appsv1.ReplicaSetList, error) {
	return c.clientset.AppsV1().ReplicaSets(namespace).List(ctx, opts)
}

func (c *Client) GetPod(ctx context.Context, namespace, name string) (*corev1.Pod, error) {
	return c.clientset.CoreV1().Pods(namespace).Get(ctx, name, metav1.GetOptions{})
}

func (c *Client) Exec(ctx context.Context, namespace, pod, container string, cmd []string) (string, error) {
	req := c.clientset.CoreV1().RESTClient().Post().
		Resource("pods").
		Name(pod).
		Namespace(namespace).
		SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Container: container,
			Command:   cmd,
			Stdout:    true,
			Stderr:    true,
		}, scheme.ParameterCodec)

	exec, err := remotecommand.NewSPDYExecutor(c.restConfig, "POST", req.URL())
	if err != nil {
		return "", fmt.Errorf("create executor: %w", err)
	}

	var stdout, stderr bytes.Buffer
	err = exec.StreamWithContext(ctx, remotecommand.StreamOptions{
		Stdout: &stdout,
		Stderr: &stderr,
	})
	if err != nil {
		return "", fmt.Errorf("exec stream: %w (stderr: %s)", err, stderr.String())
	}

	return stdout.String(), nil
}
