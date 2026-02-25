package capture

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/nex-health/ocellus/internal/cilium"
)

func testSnapshot() Snapshot {
	return Snapshot{
		Timestamp: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC),
		Pods: map[string][]cilium.Peer{
			"pod-1": {
				{Src: "10.0.0.1:1000", DstPort: 5432, Proto: "TCP", State: "established", Bytes: 1024},
			},
		},
	}
}

func testEvent() Event {
	return Event{
		Timestamp: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC),
		Kind:      EventPeerAdded,
		Pod:       "pod-1",
		Peer:      &cilium.Peer{Src: "10.0.0.1:1000", DstPort: 5432},
		Message:   "new peer connected",
	}
}

func TestJSONLFormatterSnapshot(t *testing.T) {
	f := &JSONLFormatter{}
	data, err := f.FormatSnapshot(testSnapshot())
	if err != nil {
		t.Fatalf("FormatSnapshot error: %v", err)
	}
	s := string(data)
	if !strings.HasSuffix(s, "\n") {
		t.Error("JSONL output should end with newline")
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(s)), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if parsed["type"] != "snapshot" {
		t.Errorf("type = %v, want snapshot", parsed["type"])
	}
	if _, ok := parsed["timestamp"]; !ok {
		t.Error("missing timestamp field")
	}
}

func TestJSONLFormatterEvent(t *testing.T) {
	f := &JSONLFormatter{}
	data, err := f.FormatEvent(testEvent())
	if err != nil {
		t.Fatalf("FormatEvent error: %v", err)
	}
	s := string(data)
	if !strings.HasSuffix(s, "\n") {
		t.Error("JSONL output should end with newline")
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(s)), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if parsed["type"] != "event" {
		t.Errorf("type = %v, want event", parsed["type"])
	}
}

func TestJSONFormatterSnapshot(t *testing.T) {
	f := &JSONFormatter{}
	data, err := f.FormatSnapshot(testSnapshot())
	if err != nil {
		t.Fatalf("FormatSnapshot error: %v", err)
	}
	s := string(data)
	if !strings.Contains(s, "\n  ") {
		t.Error("JSON output should be pretty-printed")
	}
	if !strings.HasSuffix(s, "\n") {
		t.Error("JSON output should end with newline")
	}
	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
}

func TestJSONFormatterEvent(t *testing.T) {
	f := &JSONFormatter{}
	data, err := f.FormatEvent(testEvent())
	if err != nil {
		t.Fatalf("FormatEvent error: %v", err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
}

func TestCSVFormatterSnapshot(t *testing.T) {
	f := NewCSVFormatter()
	data, err := f.FormatSnapshot(testSnapshot())
	if err != nil {
		t.Fatalf("FormatSnapshot error: %v", err)
	}
	s := string(data)
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines (header+row), got %d: %q", len(lines), s)
	}
	if !strings.HasPrefix(lines[0], "timestamp,") {
		t.Errorf("header should start with timestamp, got %q", lines[0])
	}
	if !strings.Contains(lines[1], "pod-1") {
		t.Error("data row should contain pod name")
	}
}

func TestCSVFormatterEvent(t *testing.T) {
	f := NewCSVFormatter()
	data, err := f.FormatEvent(testEvent())
	if err != nil {
		t.Fatalf("FormatEvent error: %v", err)
	}
	s := string(data)
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d", len(lines))
	}
	if !strings.Contains(lines[1], "peer_added") {
		t.Error("event row should contain event kind")
	}
}

func TestCSVFormatterOmitsHeaderAfterFirst(t *testing.T) {
	f := NewCSVFormatter()
	_, _ = f.FormatSnapshot(testSnapshot())
	data, err := f.FormatSnapshot(testSnapshot())
	if err != nil {
		t.Fatalf("FormatSnapshot error: %v", err)
	}
	s := string(data)
	if strings.Contains(s, "timestamp,") {
		t.Error("second call should not include header row")
	}
}

func TestTextFormatterSnapshot(t *testing.T) {
	f := &TextFormatter{}
	data, err := f.FormatSnapshot(testSnapshot())
	if err != nil {
		t.Fatalf("FormatSnapshot error: %v", err)
	}
	s := string(data)
	if !strings.Contains(s, "2026-01-01T12:00:00Z") {
		t.Error("should contain RFC3339 timestamp")
	}
	if !strings.Contains(s, "pod-1") {
		t.Error("should contain pod name")
	}
	if !strings.Contains(s, "10.0.0.1:1000") {
		t.Error("should contain peer address")
	}
}

func TestTextFormatterEvent(t *testing.T) {
	f := &TextFormatter{}
	data, err := f.FormatEvent(testEvent())
	if err != nil {
		t.Fatalf("FormatEvent error: %v", err)
	}
	s := string(data)
	if !strings.Contains(s, "peer_added") {
		t.Error("should contain event kind")
	}
	if !strings.Contains(s, "pod-1") {
		t.Error("should contain pod name")
	}
}

func TestNewFormatter(t *testing.T) {
	tests := []struct {
		name   string
		format string
		want   string
	}{
		{"jsonl", "jsonl", "*capture.JSONLFormatter"},
		{"json", "json", "*capture.JSONFormatter"},
		{"csv", "csv", "*capture.CSVFormatter"},
		{"text", "text", "*capture.TextFormatter"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := NewFormatter(tt.format)
			if err != nil {
				t.Fatalf("NewFormatter(%q) error: %v", tt.format, err)
			}
			got := fmt.Sprintf("%T", f)
			if got != tt.want {
				t.Errorf("NewFormatter(%q) type = %s, want %s", tt.format, got, tt.want)
			}
		})
	}
}

func TestNewFormatterInvalid(t *testing.T) {
	_, err := NewFormatter("xml")
	if err == nil {
		t.Error("NewFormatter(xml) should return error")
	}
}

func TestJSONLSnapshotContainsPeerFields(t *testing.T) {
	f := &JSONLFormatter{}
	snap := Snapshot{
		Timestamp: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC),
		Pods: map[string][]cilium.Peer{
			"pod-1": {{
				Src: "10.0.0.1:1000", DstPort: 5432, Proto: "TCP",
				State: "established", Bytes: 1024, RxBytes: 512, TxBytes: 512,
			}},
		},
	}
	data, _ := f.FormatSnapshot(snap)
	s := string(data)
	if !strings.Contains(s, `"src"`) {
		t.Error("JSON should contain src field")
	}
	if !strings.Contains(s, `"dst_port"`) {
		t.Error("JSON should contain dst_port field")
	}
	if !strings.Contains(s, `"rx_bytes"`) {
		t.Error("JSON should contain rx_bytes field")
	}
}
