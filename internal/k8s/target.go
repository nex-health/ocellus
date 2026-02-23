package k8s

import (
	"fmt"
	"strings"
)

type Target struct {
	Kind string // "deployment", "statefulset", "daemonset", "pod"
	Name string
}

var validKinds = map[string]bool{
	"deployment":  true,
	"statefulset": true,
	"daemonset":   true,
	"pod":         true,
}

func ParseTarget(s string) (Target, error) {
	if s == "" {
		return Target{}, fmt.Errorf("empty target")
	}

	parts := strings.SplitN(s, "/", 2)
	if len(parts) == 1 {
		return Target{Kind: "pod", Name: s}, nil
	}

	kind, name := parts[0], parts[1]
	if kind == "" || name == "" {
		return Target{}, fmt.Errorf("invalid target %q: kind and name must be non-empty", s)
	}
	if !validKinds[kind] {
		return Target{}, fmt.Errorf("unsupported workload kind %q (supported: deployment, statefulset, daemonset, pod)", kind)
	}
	return Target{Kind: kind, Name: name}, nil
}
