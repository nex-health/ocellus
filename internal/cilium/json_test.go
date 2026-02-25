package cilium

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net"
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

func TestParseJSONCTOutput_DirectionOut(t *testing.T) {
	// For OUT entries, SourceAddr = pod, DestAddr = remote.
	entries := []ctMapRecord{
		{
			Key: ctKey{
				TupleKey4: &tupleKey4{
					DestAddr:   encodeIPv4(10, 4, 166, 193), // remote
					SourceAddr: encodeIPv4(10, 4, 34, 6),    // pod
					DestPort:   networkPort(5432),            // remote port
					SourcePort: networkPort(52628),           // pod ephemeral port
					NextHeader: 6,
					Flags:      2, // OUT direction (bit 0 not set)
				},
			},
			Value: ctValue{Bytes: 500, Packets: 10},
		},
	}
	data, _ := json.Marshal(entries)

	// Explicit IN filter should exclude this.
	peers, err := ParseJSONCTOutput(string(data), "10.4.34.6", Filter{Directions: []string{"in"}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(peers) != 0 {
		t.Fatalf("IN filter should exclude OUT entries, got %d", len(peers))
	}

	// OUT filter should include it.
	peers, err = ParseJSONCTOutput(string(data), "10.4.34.6", Filter{
		Directions: []string{"out"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(peers) != 1 {
		t.Fatalf("expected 1 OUT peer, got %d", len(peers))
	}
	if peers[0].Src != "10.4.166.193:5432" {
		t.Errorf("Src = %q, want 10.4.166.193:5432", peers[0].Src)
	}
	if peers[0].DstPort != 5432 {
		t.Errorf("DstPort = %d, want 5432", peers[0].DstPort)
	}
	if peers[0].Direction != "out" {
		t.Errorf("Direction = %q, want out", peers[0].Direction)
	}
}

func TestParseJSONCTOutput_DirectionAll(t *testing.T) {
	entries := []ctMapRecord{
		{
			// IN entry.
			Key: ctKey{
				TupleKey4: &tupleKey4{
					DestAddr:   encodeIPv4(10, 4, 34, 6),    // pod
					SourceAddr: encodeIPv4(10, 4, 166, 193), // remote
					DestPort:   networkPort(4143),
					SourcePort: networkPort(52628),
					NextHeader: 6,
					Flags:      1, // IN
				},
			},
			Value: ctValue{Bytes: 100},
		},
		{
			// OUT entry.
			Key: ctKey{
				TupleKey4: &tupleKey4{
					DestAddr:   encodeIPv4(10, 4, 166, 193), // remote
					SourceAddr: encodeIPv4(10, 4, 34, 6),    // pod
					DestPort:   networkPort(52628),
					SourcePort: networkPort(4143),
					NextHeader: 6,
					Flags:      2, // OUT
				},
			},
			Value: ctValue{Bytes: 200},
		},
	}
	data, _ := json.Marshal(entries)

	peers, err := ParseJSONCTOutput(string(data), "10.4.34.6", Filter{
		Directions: []string{"in", "out"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(peers) != 2 {
		t.Fatalf("expected 2 peers (IN + OUT), got %d", len(peers))
	}

	inCount, outCount := 0, 0
	for _, p := range peers {
		switch p.Direction {
		case "in":
			inCount++
		case "out":
			outCount++
		}
	}
	if inCount != 1 || outCount != 1 {
		t.Errorf("expected 1 IN + 1 OUT, got %d IN + %d OUT", inCount, outCount)
	}
}

func TestParseJSONCTOutput_DirectionField(t *testing.T) {
	entries := []ctMapRecord{
		{
			Key: ctKey{
				TupleKey4: &tupleKey4{
					DestAddr:   encodeIPv4(10, 4, 34, 6),
					SourceAddr: encodeIPv4(10, 4, 166, 193),
					DestPort:   networkPort(4143),
					SourcePort: networkPort(52628),
					NextHeader: 6,
					Flags:      1, // IN
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
	if len(peers) != 1 {
		t.Fatalf("expected 1 peer, got %d", len(peers))
	}
	if peers[0].Direction != "in" {
		t.Errorf("Direction = %q, want in", peers[0].Direction)
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

func TestParseJSONCTOutput_ServiceFlag(t *testing.T) {
	// TUPLE_F_IN=1, TUPLE_F_SERVICE=4 → Flags=5 (IN + SERVICE).
	// Entries with additional flag bits should still be recognized as inbound.
	entries := []ctMapRecord{
		{
			Key: ctKey{
				TupleKey4: &tupleKey4{
					DestAddr:   encodeIPv4(10, 1, 0, 1),
					SourceAddr: encodeIPv4(10, 0, 0, 1),
					DestPort:   networkPort(53),
					SourcePort: networkPort(2000),
					NextHeader: 17, // UDP
					Flags:      5,  // IN | SERVICE
				},
			},
			Value: ctValue{Bytes: 300},
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
		t.Fatalf("expected 1 peer with service flag, got %d", len(peers))
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

func TestDecodeIPv4_InvalidBase64(t *testing.T) {
	_, err := decodeIPv4("!!!not-base64!!!")
	if err == nil {
		t.Fatal("expected error for invalid base64")
	}
}

func TestDecodeIPv4_WrongLength(t *testing.T) {
	// Valid base64 but not 4 bytes.
	short := base64.StdEncoding.EncodeToString([]byte{1, 2})
	_, err := decodeIPv4(short)
	if err == nil {
		t.Fatal("expected error for wrong-length data")
	}
}

func TestParseJSONCTOutput_SrcCIDRFilter(t *testing.T) {
	entries := []ctMapRecord{
		{
			Key: ctKey{TupleKey4: &tupleKey4{
				DestAddr: encodeIPv4(10, 1, 0, 1), SourceAddr: encodeIPv4(10, 4, 166, 193),
				DestPort: networkPort(5432), SourcePort: networkPort(1000),
				NextHeader: 6, Flags: 1,
			}},
			Value: ctValue{Bytes: 100},
		},
		{
			Key: ctKey{TupleKey4: &tupleKey4{
				DestAddr: encodeIPv4(10, 1, 0, 1), SourceAddr: encodeIPv4(192, 168, 1, 1),
				DestPort: networkPort(5432), SourcePort: networkPort(2000),
				NextHeader: 6, Flags: 1,
			}},
			Value: ctValue{Bytes: 200},
		},
	}
	data, _ := json.Marshal(entries)

	_, cidr, _ := net.ParseCIDR("10.4.166.0/24")
	peers, err := ParseJSONCTOutput(string(data), "10.1.0.1", Filter{
		PortMin: 5432, PortMax: 5432,
		SrcCIDR: cidr,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(peers) != 1 {
		t.Fatalf("expected 1 peer from CIDR, got %d", len(peers))
	}
	if peers[0].Src != "10.4.166.193:1000" {
		t.Errorf("Src = %q, want 10.4.166.193:1000", peers[0].Src)
	}
}

func TestParseJSONCTOutput_NilTupleKey4(t *testing.T) {
	entries := []ctMapRecord{
		{
			Key:   ctKey{TupleKey4: nil, TupleKey6: nil},
			Value: ctValue{Bytes: 100},
		},
	}
	data, _ := json.Marshal(entries)

	peers, err := ParseJSONCTOutput(string(data), "10.1.0.1", Filter{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(peers) != 0 {
		t.Fatalf("expected 0 peers for nil key entries, got %d", len(peers))
	}
}

func TestParseJSONCTOutput_PortRangeFilter(t *testing.T) {
	entries := []ctMapRecord{
		{
			Key: ctKey{TupleKey4: &tupleKey4{
				DestAddr: encodeIPv4(10, 1, 0, 1), SourceAddr: encodeIPv4(10, 0, 0, 1),
				DestPort: networkPort(5432), SourcePort: networkPort(1000),
				NextHeader: 6, Flags: 1,
			}},
			Value: ctValue{Bytes: 100},
		},
		{
			Key: ctKey{TupleKey4: &tupleKey4{
				DestAddr: encodeIPv4(10, 1, 0, 1), SourceAddr: encodeIPv4(10, 0, 0, 2),
				DestPort: networkPort(5440), SourcePort: networkPort(2000),
				NextHeader: 6, Flags: 1,
			}},
			Value: ctValue{Bytes: 200},
		},
		{
			Key: ctKey{TupleKey4: &tupleKey4{
				DestAddr: encodeIPv4(10, 1, 0, 1), SourceAddr: encodeIPv4(10, 0, 0, 3),
				DestPort: networkPort(6000), SourcePort: networkPort(3000),
				NextHeader: 6, Flags: 1,
			}},
			Value: ctValue{Bytes: 300},
		},
	}
	data, _ := json.Marshal(entries)

	peers, err := ParseJSONCTOutput(string(data), "10.1.0.1", Filter{PortMin: 5432, PortMax: 5440})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(peers) != 2 {
		t.Fatalf("expected 2 peers in port range, got %d", len(peers))
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
		execFn: func(_, _, _ string, cmd []string) (string, error) {
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

func encodeIPv6(ip net.IP) string {
	b := ip.To16()
	if b == nil {
		panic("not a valid IPv6 address")
	}
	return base64.StdEncoding.EncodeToString(b)
}

func TestDecodeIPv6(t *testing.T) {
	ip := net.ParseIP("f00d::a0f:0:0:4870")
	encoded := encodeIPv6(ip)
	decoded, err := decodeIPv6(encoded)
	if err != nil {
		t.Fatalf("decodeIPv6 error: %v", err)
	}
	if !decoded.Equal(ip) {
		t.Errorf("decoded = %s, want %s", decoded, ip)
	}
}

func TestDecodeIPv6_InvalidBase64(t *testing.T) {
	_, err := decodeIPv6("!!!not-base64!!!")
	if err == nil {
		t.Fatal("expected error for invalid base64")
	}
}

func TestDecodeIPv6_WrongLength(t *testing.T) {
	short := base64.StdEncoding.EncodeToString([]byte{1, 2, 3, 4})
	_, err := decodeIPv6(short)
	if err == nil {
		t.Fatal("expected error for wrong-length data")
	}
}

func TestParseJSONCTOutput_IPv6(t *testing.T) {
	podIP := net.ParseIP("f00d::a0f:0:0:4264")
	peerIP := net.ParseIP("f00d::a0f:0:0:4870")

	entries := []ctMapRecord{
		{
			Key: ctKey{
				TupleKey6: &tupleKey6{
					DestAddr:   encodeIPv6(podIP),
					SourceAddr: encodeIPv6(peerIP),
					DestPort:   networkPort(80),
					SourcePort: networkPort(34274),
					NextHeader: 6,
					Flags:      1, // IN
				},
			},
			Value: ctValue{
				Packets:      5,
				Bytes:        452,
				Lifetime:     277365,
				RxFlagsSeen:  0x02,
				TxFlagsSeen:  0x12,
				LastRxReport: 277355,
				LastTxReport: 277355,
			},
		},
	}
	data, _ := json.Marshal(entries)

	peers, err := ParseJSONCTOutput(string(data), "f00d::a0f:0:0:4264", Filter{PortMin: 80, PortMax: 80})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(peers) != 1 {
		t.Fatalf("expected 1 peer, got %d", len(peers))
	}
	if peers[0].Src != "[f00d::a0f:0:0:4870]:34274" {
		t.Errorf("Src = %q, want [f00d::a0f:0:0:4870]:34274", peers[0].Src)
	}
	if peers[0].DstPort != 80 {
		t.Errorf("DstPort = %d, want 80", peers[0].DstPort)
	}
	if peers[0].IPVersion != "6" {
		t.Errorf("IPVersion = %q, want 6", peers[0].IPVersion)
	}
	if peers[0].Proto != "TCP" {
		t.Errorf("Proto = %q, want TCP", peers[0].Proto)
	}
	if peers[0].Direction != "in" {
		t.Errorf("Direction = %q, want in", peers[0].Direction)
	}
}

func TestParseJSONCTOutput_IPv6Mixed(t *testing.T) {
	podIPv4 := net.ParseIP("10.4.34.6")
	podIPv6 := net.ParseIP("f00d::a0f:0:0:4264")
	peerIPv4 := net.ParseIP("10.4.166.193")
	peerIPv6 := net.ParseIP("f00d::a0f:0:0:4870")

	entries := []ctMapRecord{
		{
			Key: ctKey{
				TupleKey4: &tupleKey4{
					DestAddr:   encodeIPv4(podIPv4[12], podIPv4[13], podIPv4[14], podIPv4[15]),
					SourceAddr: encodeIPv4(peerIPv4[12], peerIPv4[13], peerIPv4[14], peerIPv4[15]),
					DestPort:   networkPort(4143),
					SourcePort: networkPort(52628),
					NextHeader: 6,
					Flags:      1,
				},
			},
			Value: ctValue{Bytes: 100},
		},
		{
			Key: ctKey{
				TupleKey6: &tupleKey6{
					DestAddr:   encodeIPv6(podIPv6),
					SourceAddr: encodeIPv6(peerIPv6),
					DestPort:   networkPort(80),
					SourcePort: networkPort(34274),
					NextHeader: 6,
					Flags:      1,
				},
			},
			Value: ctValue{Bytes: 200},
		},
	}
	data, _ := json.Marshal(entries)

	// Parse for v4 pod.
	v4Peers, err := ParseJSONCTOutput(string(data), "10.4.34.6", Filter{})
	if err != nil {
		t.Fatalf("v4 error: %v", err)
	}
	if len(v4Peers) != 1 {
		t.Fatalf("expected 1 v4 peer, got %d", len(v4Peers))
	}
	if v4Peers[0].IPVersion != "4" {
		t.Errorf("IPVersion = %q, want 4", v4Peers[0].IPVersion)
	}

	// Parse for v6 pod.
	v6Peers, err := ParseJSONCTOutput(string(data), "f00d::a0f:0:0:4264", Filter{})
	if err != nil {
		t.Fatalf("v6 error: %v", err)
	}
	if len(v6Peers) != 1 {
		t.Fatalf("expected 1 v6 peer, got %d", len(v6Peers))
	}
	if v6Peers[0].IPVersion != "6" {
		t.Errorf("IPVersion = %q, want 6", v6Peers[0].IPVersion)
	}
}

func TestParseJSONCTOutput_IPv4HasIPVersion(t *testing.T) {
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
			Value: ctValue{Bytes: 100},
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
	if peers[0].IPVersion != "4" {
		t.Errorf("IPVersion = %q, want 4", peers[0].IPVersion)
	}
}
