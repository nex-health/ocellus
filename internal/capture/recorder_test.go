package capture

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nex-health/ocellus/internal/cilium"
)

func TestRecorderDumpSnapshot(t *testing.T) {
	var buf bytes.Buffer
	r := NewRecorder(&JSONLFormatter{}, NewStreamWriter(&buf))

	snap := Snapshot{
		Timestamp: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC),
		Pods: map[string][]cilium.Peer{
			"pod-1": {{Src: "10.0.0.1:1000", DstPort: 5432}},
		},
	}

	if err := r.DumpSnapshot(snap); err != nil {
		t.Fatalf("DumpSnapshot error: %v", err)
	}

	output := buf.String()
	if output == "" {
		t.Fatal("expected output")
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(strings.TrimSpace(output)), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if parsed["type"] != "snapshot" {
		t.Errorf("type = %v, want snapshot", parsed["type"])
	}
}

func TestRecorderContinuousRecording(t *testing.T) {
	var buf bytes.Buffer
	r := NewRecorder(&JSONLFormatter{}, NewStreamWriter(&buf))
	r.SetContinuous(true)

	snap1 := Snapshot{
		Timestamp: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC),
		Pods:      map[string][]cilium.Peer{"pod-1": {{Src: "10.0.0.1:1000"}}},
	}
	snap2 := Snapshot{
		Timestamp: time.Date(2026, 1, 1, 12, 0, 10, 0, time.UTC),
		Pods:      map[string][]cilium.Peer{"pod-1": {{Src: "10.0.0.1:1000"}}},
	}

	if err := r.OnPoll(snap1); err != nil {
		t.Fatalf("OnPoll 1 error: %v", err)
	}
	if err := r.OnPoll(snap2); err != nil {
		t.Fatalf("OnPoll 2 error: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	snapshotCount := 0
	for _, line := range lines {
		var parsed map[string]interface{}
		if err := json.Unmarshal([]byte(line), &parsed); err == nil {
			if parsed["type"] == "snapshot" {
				snapshotCount++
			}
		}
	}
	if snapshotCount < 2 {
		t.Errorf("expected >= 2 snapshots, got %d", snapshotCount)
	}
}

func TestRecorderEventsEmitted(t *testing.T) {
	var buf bytes.Buffer
	r := NewRecorder(&JSONLFormatter{}, NewStreamWriter(&buf))
	r.SetContinuous(true)

	snap1 := Snapshot{
		Timestamp: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC),
		Pods:      map[string][]cilium.Peer{"pod-1": {}},
	}
	snap2 := Snapshot{
		Timestamp: time.Date(2026, 1, 1, 12, 0, 10, 0, time.UTC),
		Pods: map[string][]cilium.Peer{
			"pod-1": {{Src: "10.0.0.1:1000", DstPort: 5432}},
		},
	}

	_ = r.OnPoll(snap1)
	_ = r.OnPoll(snap2)

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	eventFound := false
	for _, line := range lines {
		var parsed map[string]interface{}
		if err := json.Unmarshal([]byte(line), &parsed); err == nil {
			if parsed["type"] == "event" {
				eventFound = true
			}
		}
	}
	if !eventFound {
		t.Error("expected event lines in output")
	}
}

func TestRecorderNoContinuousNoOutput(t *testing.T) {
	var buf bytes.Buffer
	r := NewRecorder(&JSONLFormatter{}, NewStreamWriter(&buf))

	// First poll to establish baseline (will emit pod_discovered).
	snap1 := Snapshot{
		Timestamp: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC),
		Pods:      map[string][]cilium.Peer{"pod-1": {}},
	}
	_ = r.OnPoll(snap1)
	buf.Reset()

	// Second poll with same state should produce no output when continuous is off.
	snap2 := Snapshot{
		Timestamp: time.Date(2026, 1, 1, 12, 0, 10, 0, time.UTC),
		Pods:      map[string][]cilium.Peer{"pod-1": {}},
	}
	_ = r.OnPoll(snap2)
	if buf.String() != "" {
		t.Error("expected no output when continuous is off and no events")
	}
}

func TestRecorderIsContinuous(t *testing.T) {
	var buf bytes.Buffer
	r := NewRecorder(&JSONLFormatter{}, NewStreamWriter(&buf))
	if r.IsContinuous() {
		t.Error("should not be continuous by default")
	}
	r.SetContinuous(true)
	if !r.IsContinuous() {
		t.Error("should be continuous after SetContinuous(true)")
	}
}

func TestRecorderPath(t *testing.T) {
	// With a StreamWriter, Path() returns empty.
	var buf bytes.Buffer
	r := NewRecorder(&JSONLFormatter{}, NewStreamWriter(&buf))
	if got := r.Path(); got != "" {
		t.Errorf("Path() with StreamWriter = %q, want empty", got)
	}

	// With a FileWriter, Path() returns the file path.
	dir := t.TempDir()
	path := filepath.Join(dir, "test.jsonl")
	fw, err := NewFileWriter(path)
	if err != nil {
		t.Fatalf("NewFileWriter: %v", err)
	}
	defer func() {
		fw.Close()
		os.Remove(path)
	}()
	r2 := NewRecorder(&JSONLFormatter{}, fw)
	if got := r2.Path(); got != path {
		t.Errorf("Path() with FileWriter = %q, want %q", got, path)
	}
}
