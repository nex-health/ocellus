package display

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestRenderCycle(t *testing.T) {
	var buf bytes.Buffer
	pods := []PodStatus{
		{Name: "pgbouncer-abc-pod1", Active: true, Peers: []string{"10.0.0.1:1234", "10.0.0.2:5678"}},
		{Name: "pgbouncer-abc-pod2", Active: true, Peers: []string{"10.0.0.3:9999"}},
	}

	now := time.Date(2026, 2, 23, 12, 0, 0, 0, time.UTC)
	RenderCycle(&buf, pods, 4143, now, 80)

	output := buf.String()

	if !strings.Contains(output, ":4143") {
		t.Error("expected port in header")
	}
	if !strings.Contains(output, "2/2 active") {
		t.Error("expected active count")
	}
	if !strings.Contains(output, "3 connections") {
		t.Error("expected total connection count")
	}
	if !strings.Contains(output, "pgbouncer-abc-pod1") {
		t.Error("expected pod1 name")
	}
	if !strings.Contains(output, "10.0.0.1:1234") {
		t.Error("expected peer address")
	}
}

func TestRenderCycle_WithExitedPod(t *testing.T) {
	var buf bytes.Buffer
	pods := []PodStatus{
		{Name: "pod-1", Active: true, Peers: []string{"10.0.0.1:1234"}},
		{Name: "pod-2", Active: false, Peers: []string{"10.0.0.2:5678"}},
	}

	now := time.Date(2026, 2, 23, 12, 0, 0, 0, time.UTC)
	RenderCycle(&buf, pods, 5432, now, 80)

	output := buf.String()
	if !strings.Contains(output, "1/2 active") {
		t.Error("expected 1/2 active")
	}
	if !strings.Contains(output, "[exited]") {
		t.Error("expected [exited] marker")
	}
	if !strings.Contains(output, "[active]") {
		t.Error("expected [active] marker")
	}
}

func TestRenderCycle_AllExited(t *testing.T) {
	var buf bytes.Buffer
	pods := []PodStatus{
		{Name: "pod-1", Active: false, Peers: nil},
	}

	now := time.Date(2026, 2, 23, 12, 0, 0, 0, time.UTC)
	RenderCycle(&buf, pods, 5432, now, 80)

	output := buf.String()
	if !strings.Contains(output, "all pods exited") {
		t.Error("expected 'all pods exited'")
	}
}

func TestWriteReport(t *testing.T) {
	var buf bytes.Buffer
	pods := []PodStatus{
		{Name: "pod-1", Active: true, Peers: []string{"10.0.0.1:1234"}},
		{Name: "pod-2", Active: false, Peers: []string{"10.0.0.2:5678"}},
	}

	now := time.Date(2026, 2, 23, 12, 0, 0, 0, time.UTC)
	WriteReport(&buf, pods, 5432, now)

	output := buf.String()
	if !strings.Contains(output, "[active]  pod-1") {
		t.Error("expected active pod in report")
	}
	if !strings.Contains(output, "[exited]  pod-2") {
		t.Error("expected exited pod in report")
	}
	if !strings.Contains(output, "10.0.0.1:1234") {
		t.Error("expected peer in report")
	}
	// Report should have no ANSI codes
	if strings.Contains(output, "\033[") {
		t.Error("report should not contain ANSI escape codes")
	}
}
