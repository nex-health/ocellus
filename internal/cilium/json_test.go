package cilium

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"testing"
)

func encodeIPv4(a, b, c, d byte) string {
	return base64.StdEncoding.EncodeToString([]byte{a, b, c, d})
}

func networkPort(port uint16) uint16 {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, port)
	return binary.LittleEndian.Uint16(buf)
}

func TestParseJSONCTOutput(t *testing.T) {
	entries := []ctMapRecord{
		{
			Key: ctKey{
				TupleKey4: &tupleKey4{
					DestAddr:   encodeIPv4(10, 4, 34, 6),
					SourceAddr: encodeIPv4(10, 4, 166, 193),
					DestPort:   networkPort(4143),
					SourcePort: networkPort(52628),
					NextHeader: 6,
					Flags:      1,
				},
			},
			Value: ctValue{
				Packets:          5,
				Bytes:            452,
				Lifetime:         277365,
				RxFlagsSeen:      0x02,
				TxFlagsSeen:      0x12,
				LastRxReport:     277355,
				LastTxReport:     277355,
				SourceSecurityID: 2,
			},
		},
	}
	data, _ := json.Marshal(entries)

	peers, err := ParseJSONCTOutput(string(data), "10.4.34.6", Filter{PortMin: 4143, PortMax: 4143})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(peers) != 1 {
		t.Fatalf("expected 1 peer, got %d", len(peers))
	}
	if peers[0].Src != "10.4.166.193:52628" {
		t.Errorf("Src = %q, want 10.4.166.193:52628", peers[0].Src)
	}
	if peers[0].Bytes != 452 {
		t.Errorf("Bytes = %d, want 452", peers[0].Bytes)
	}
	if peers[0].Proto != "TCP" {
		t.Errorf("Proto = %q, want TCP", peers[0].Proto)
	}
	if peers[0].RxFlagsSeen != 0x02 {
		t.Errorf("RxFlagsSeen = %x, want 02", peers[0].RxFlagsSeen)
	}
}

func TestParseJSONCTOutput_FiltersOUT(t *testing.T) {
	entries := []ctMapRecord{
		{
			Key: ctKey{
				TupleKey4: &tupleKey4{
					DestAddr:   encodeIPv4(10, 4, 34, 6),
					SourceAddr: encodeIPv4(10, 4, 166, 193),
					DestPort:   networkPort(4143),
					SourcePort: networkPort(52628),
					NextHeader: 6,
					Flags:      2, // OUT direction
				},
			},
			Value: ctValue{Bytes: 100},
		},
	}
	data, _ := json.Marshal(entries)

	peers, err := ParseJSONCTOutput(string(data), "10.4.34.6", Filter{PortMin: 4143, PortMax: 4143})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(peers) != 0 {
		t.Fatalf("expected 0 peers (OUT should be filtered), got %d", len(peers))
	}
}

func TestParseJSONCTOutput_InvalidJSON(t *testing.T) {
	_, err := ParseJSONCTOutput("not json", "10.4.34.6", Filter{})
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestParseJSONCTOutput_UDP(t *testing.T) {
	entries := []ctMapRecord{
		{
			Key: ctKey{
				TupleKey4: &tupleKey4{
					DestAddr:   encodeIPv4(10, 1, 0, 1),
					SourceAddr: encodeIPv4(10, 0, 0, 1),
					DestPort:   networkPort(53),
					SourcePort: networkPort(1000),
					NextHeader: 17, // UDP
					Flags:      1,
				},
			},
			Value: ctValue{Bytes: 200},
		},
	}
	data, _ := json.Marshal(entries)

	peers, err := ParseJSONCTOutput(string(data), "10.1.0.1", Filter{
		PortMin: 53, PortMax: 53,
		Protos: []string{"UDP"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(peers) != 1 {
		t.Fatalf("expected 1 UDP peer, got %d", len(peers))
	}
	if peers[0].Proto != "UDP" {
		t.Errorf("Proto = %q, want UDP", peers[0].Proto)
	}
}

func TestParseJSONCTOutput_StateClosing(t *testing.T) {
	entries := []ctMapRecord{
		{
			Key: ctKey{
				TupleKey4: &tupleKey4{
					DestAddr:   encodeIPv4(10, 4, 34, 6),
					SourceAddr: encodeIPv4(10, 4, 166, 193),
					DestPort:   networkPort(4143),
					SourcePort: networkPort(52628),
					NextHeader: 6,
					Flags:      1,
				},
			},
			Value: ctValue{
				Flags: 0x0001, // RxClosing
				Bytes: 300,
			},
		},
	}
	data, _ := json.Marshal(entries)

	// Default filter (established only) should exclude closing.
	peers, err := ParseJSONCTOutput(string(data), "10.4.34.6", Filter{PortMin: 4143, PortMax: 4143})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(peers) != 0 {
		t.Fatalf("expected 0 peers (closing excluded by default), got %d", len(peers))
	}

	// Closing filter should include it.
	peers, err = ParseJSONCTOutput(string(data), "10.4.34.6", Filter{
		PortMin: 4143, PortMax: 4143,
		States: []string{"closing"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(peers) != 1 {
		t.Fatalf("expected 1 closing peer, got %d", len(peers))
	}
	if peers[0].State != "closing" {
		t.Errorf("State = %q, want closing", peers[0].State)
	}
}

func TestJSONSourceQueryPeers(t *testing.T) {
	// Build sample JSON output.
	entries := []ctMapRecord{
		{
			Key: ctKey{
				TupleKey4: &tupleKey4{
					DestAddr:   encodeIPv4(10, 4, 34, 6),
					SourceAddr: encodeIPv4(10, 4, 166, 193),
					DestPort:   networkPort(4143),
					SourcePort: networkPort(52628),
					NextHeader: 6,
					Flags:      1,
				},
			},
			Value: ctValue{
				Packets:          5,
				Bytes:            452,
				Lifetime:         277365,
				RxFlagsSeen:      0x02,
				TxFlagsSeen:      0x12,
				LastRxReport:     277355,
				LastTxReport:     277355,
				SourceSecurityID: 2,
			},
		},
	}
	jsonData, _ := json.Marshal(entries)

	client := &mockPodExecer{
		execFn: func(namespace, pod, container string, cmd []string) (string, error) {
			// Verify the command includes -o json.
			if len(cmd) < 7 || cmd[5] != "-o" || cmd[6] != "json" {
				t.Errorf("expected -o json in cmd, got %v", cmd)
			}
			return string(jsonData), nil
		},
	}

	src := &JSONSource{}
	results, err := src.QueryPeers(context.Background(), client, "cilium-abc", []string{"10.4.34.6"}, Filter{PortMin: 4143, PortMax: 4143})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	peers := results["10.4.34.6"]
	if len(peers) != 1 {
		t.Fatalf("expected 1 peer, got %d", len(peers))
	}
	if peers[0].Src != "10.4.166.193:52628" {
		t.Errorf("Src = %q, want 10.4.166.193:52628", peers[0].Src)
	}
	if peers[0].Bytes != 452 {
		t.Errorf("Bytes = %d, want 452", peers[0].Bytes)
	}
}
