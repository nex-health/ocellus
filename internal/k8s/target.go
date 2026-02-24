package k8s

import (
	"fmt"
	"strings"
)

type Target struct {
	Kind string // "deployment", "statefulset", "daemonset", "pod"
	Name string
}

// kindAliases maps kubectl-style short names to canonical kind names.
var kindAliases = map[string]string{
	"deployment":  "deployment",
	"deploy":      "deployment",
	"replicaset":  "replicaset",
	"rs":          "replicaset",
	"statefulset": "statefulset",
	"sts":         "statefulset",
	"daemonset":   "daemonset",
	"ds":          "daemonset",
	"pod":         "pod",
	"po":          "pod",
}

func ParseTarget(s string) (Target, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return Target{}, fmt.Errorf("empty target")
	}

	parts := strings.SplitN(s, "/", 2)
	if len(parts) == 1 {
		return Target{Kind: "pod", Name: s}, nil
	}

	kind := strings.TrimSpace(parts[0])
	name := strings.TrimSpace(parts[1])
	if kind == "" || name == "" {
		return Target{}, fmt.Errorf("invalid target %q: kind and name must be non-empty", s)
	}
	canonical, ok := kindAliases[strings.ToLower(kind)]
	if !ok {
		return Target{}, fmt.Errorf("unsupported workload kind %q (supported: deployment/deploy, statefulset/sts, daemonset/ds, replicaset/rs, pod/po)", kind)
	}
	return Target{Kind: canonical, Name: name}, nil
}
