package capture

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Formatter serializes snapshots and events to bytes.
type Formatter interface {
	FormatSnapshot(Snapshot) ([]byte, error)
	FormatEvent(Event) ([]byte, error)
}

// jsonlSnapshot wraps a Snapshot with a type discriminator for JSONL output.
type jsonlSnapshot struct {
	Type string `json:"type"`
	Snapshot
}

// jsonlEvent wraps an Event with a type discriminator for JSONL output.
type jsonlEvent struct {
	Type string `json:"type"`
	Event
}

// JSONLFormatter outputs one JSON object per line.
type JSONLFormatter struct{}

func (f *JSONLFormatter) FormatSnapshot(s Snapshot) ([]byte, error) {
	data, err := json.Marshal(jsonlSnapshot{Type: "snapshot", Snapshot: s})
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func (f *JSONLFormatter) FormatEvent(e Event) ([]byte, error) {
	data, err := json.Marshal(jsonlEvent{Type: "event", Event: e})
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

// JSONFormatter outputs pretty-printed JSON.
type JSONFormatter struct{}

func (f *JSONFormatter) FormatSnapshot(s Snapshot) ([]byte, error) {
	data, err := json.MarshalIndent(jsonlSnapshot{Type: "snapshot", Snapshot: s}, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func (f *JSONFormatter) FormatEvent(e Event) ([]byte, error) {
	data, err := json.MarshalIndent(jsonlEvent{Type: "event", Event: e}, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

// CSVFormatter outputs CSV rows. The header is written only once.
type CSVFormatter struct {
	snapshotHeaderWritten bool
	eventHeaderWritten    bool
}

// NewCSVFormatter creates a new CSVFormatter.
func NewCSVFormatter() *CSVFormatter {
	return &CSVFormatter{}
}

var snapshotCSVHeader = []string{
	"timestamp", "pod", "src", "dst_port", "proto", "state", "direction", "ip_version",
	"bytes", "packets", "rx_bytes", "tx_bytes", "rx_packets", "tx_packets",
	"expires", "last_rx_report", "last_tx_report", "rx_flags_seen", "tx_flags_seen",
}

var eventCSVHeader = []string{
	"timestamp", "kind", "pod", "peer_src", "message",
}

func (f *CSVFormatter) FormatSnapshot(s Snapshot) ([]byte, error) {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)

	if !f.snapshotHeaderWritten {
		if err := w.Write(snapshotCSVHeader); err != nil {
			return nil, err
		}
		f.snapshotHeaderWritten = true
	}

	podNames := make([]string, 0, len(s.Pods))
	for name := range s.Pods {
		podNames = append(podNames, name)
	}
	sort.Strings(podNames)

	ts := s.Timestamp.Format("2006-01-02T15:04:05Z07:00")
	for _, podName := range podNames {
		for _, p := range s.Pods[podName] {
			row := []string{
				ts, podName, p.Src, fmt.Sprintf("%d", p.DstPort), p.Proto, p.State, p.Direction, p.IPVersion,
				fmt.Sprintf("%d", p.Bytes), fmt.Sprintf("%d", p.Packets),
				fmt.Sprintf("%d", p.RxBytes), fmt.Sprintf("%d", p.TxBytes),
				fmt.Sprintf("%d", p.RxPackets), fmt.Sprintf("%d", p.TxPackets),
				fmt.Sprintf("%d", p.Expires), fmt.Sprintf("%d", p.LastRxReport),
				fmt.Sprintf("%d", p.LastTxReport), fmt.Sprintf("%d", p.RxFlagsSeen),
				fmt.Sprintf("%d", p.TxFlagsSeen),
			}
			if err := w.Write(row); err != nil {
				return nil, err
			}
		}
	}
	w.Flush()
	return buf.Bytes(), w.Error()
}

func (f *CSVFormatter) FormatEvent(e Event) ([]byte, error) {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)

	if !f.eventHeaderWritten {
		if err := w.Write(eventCSVHeader); err != nil {
			return nil, err
		}
		f.eventHeaderWritten = true
	}

	peerSrc := ""
	if e.Peer != nil {
		peerSrc = e.Peer.Src
	}
	row := []string{
		e.Timestamp.Format("2006-01-02T15:04:05Z07:00"),
		string(e.Kind), e.Pod, peerSrc, e.Message,
	}
	if err := w.Write(row); err != nil {
		return nil, err
	}
	w.Flush()
	return buf.Bytes(), w.Error()
}

// TextFormatter outputs human-readable text.
type TextFormatter struct{}

func (f *TextFormatter) FormatSnapshot(s Snapshot) ([]byte, error) {
	var buf bytes.Buffer
	ts := s.Timestamp.Format("2006-01-02T15:04:05Z07:00")
	fmt.Fprintf(&buf, "--- Snapshot %s ---\n", ts)

	podNames := make([]string, 0, len(s.Pods))
	for name := range s.Pods {
		podNames = append(podNames, name)
	}
	sort.Strings(podNames)

	for _, podName := range podNames {
		peers := s.Pods[podName]
		fmt.Fprintf(&buf, "  %s (%d peers):\n", podName, len(peers))
		for _, p := range peers {
			ipv := "v4"
			if p.IPVersion == "6" {
				ipv = "v6"
			}
			fmt.Fprintf(&buf, "    %s -> :%d %s %s %s %s bytes=%d\n",
				p.Src, p.DstPort, p.Proto, p.State, p.Direction, ipv, p.Bytes)
		}
	}

	if len(s.Errors) > 0 {
		fmt.Fprintf(&buf, "  Errors: %s\n", strings.Join(s.Errors, "; "))
	}
	return buf.Bytes(), nil
}

func (f *TextFormatter) FormatEvent(e Event) ([]byte, error) {
	var buf bytes.Buffer
	ts := e.Timestamp.Format("2006-01-02T15:04:05Z07:00")
	peerInfo := ""
	if e.Peer != nil {
		peerInfo = fmt.Sprintf(" peer=%s", e.Peer.Src)
	}
	msg := ""
	if e.Message != "" {
		msg = fmt.Sprintf(" %s", e.Message)
	}
	fmt.Fprintf(&buf, "[%s] %s pod=%s%s%s\n", ts, e.Kind, e.Pod, peerInfo, msg)
	return buf.Bytes(), nil
}

// NewFormatter creates a Formatter for the given format name.
// Valid names: "jsonl", "json", "csv", "text".
func NewFormatter(format string) (Formatter, error) {
	switch format {
	case "jsonl":
		return &JSONLFormatter{}, nil
	case "json":
		return &JSONFormatter{}, nil
	case "csv":
		return NewCSVFormatter(), nil
	case "text":
		return &TextFormatter{}, nil
	default:
		return nil, fmt.Errorf("unknown format: %q (valid: jsonl, json, csv, text)", format)
	}
}
