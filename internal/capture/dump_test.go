package capture

import (
	"bytes"
	"testing"
	"time"

	"github.com/nex-health/ocellus/internal/cilium"
)

func TestDumpOnce(t *testing.T) {
	var buf bytes.Buffer
	f := &JSONLFormatter{}
	w := NewStreamWriter(&buf)

	snap := Snapshot{
		Timestamp: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC),
		Pods: map[string][]cilium.Peer{
			"pod-1": {{Src: "10.0.0.1:1000", DstPort: 5432}},
		},
	}

	err := DumpOnce(f, w, snap)
	if err != nil {
		t.Fatalf("DumpOnce error: %v", err)
	}
	if buf.Len() == 0 {
		t.Error("expected output")
	}
}
