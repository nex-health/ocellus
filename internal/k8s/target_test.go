package k8s

import "testing"

func TestParseTarget(t *testing.T) {
	tests := []struct {
		input    string
		wantKind string
		wantName string
		wantErr  bool
	}{
		{"deployment/pgbouncer", "deployment", "pgbouncer", false},
		{"deploy/pgbouncer", "deployment", "pgbouncer", false},
		{"statefulset/postgres", "statefulset", "postgres", false},
		{"sts/postgres", "statefulset", "postgres", false},
		{"daemonset/fluentd", "daemonset", "fluentd", false},
		{"ds/fluentd", "daemonset", "fluentd", false},
		{"replicaset/my-rs", "replicaset", "my-rs", false},
		{"rs/my-rs", "replicaset", "my-rs", false},
		{"pod/my-pod-xyz", "pod", "my-pod-xyz", false},
		{"po/my-pod-xyz", "pod", "my-pod-xyz", false},
		{"my-pod-xyz", "pod", "my-pod-xyz", false},
		{"Deployment/pgbouncer", "deployment", "pgbouncer", false},
		{"DEPLOY/pgbouncer", "deployment", "pgbouncer", false},
		{"", "", "", true},
		{"unknown/foo", "", "", true},
		{"deployment/", "", "", true},
		{"/name", "", "", true},
		{"deployment/  spaces  ", "deployment", "spaces", false},
		{"  bare-pod  ", "pod", "bare-pod", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			target, err := ParseTarget(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if target.Kind != tt.wantKind {
				t.Errorf("kind = %q, want %q", target.Kind, tt.wantKind)
			}
			if target.Name != tt.wantName {
				t.Errorf("name = %q, want %q", target.Name, tt.wantName)
			}
		})
	}
}
