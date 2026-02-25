package cilium

import (
	"net"
	"testing"
)

const sampleCTOutput = `TCP IN 10.4.166.193:52628 -> 10.4.34.6:4143 expires=277365 Packets=5 Bytes=452 RxFlagsSeen=0x02 LastRxReport=277355 TxFlagsSeen=0x12 LastTxReport=277355 Flags=0x0012 [ SeenNonSyn ] RevNAT=0 SourceSecurityID=2 BackendID=0
TCP IN 10.4.167.123:45120 -> 10.4.34.6:4143 expires=277400 Packets=10 Bytes=900 RxFlagsSeen=0x02 LastRxReport=277390 TxFlagsSeen=0x12 LastTxReport=277390 Flags=0x0012 [ SeenNonSyn ] RevNAT=0 SourceSecurityID=3 BackendID=0
TCP IN 10.4.167.124:43578 -> 10.4.34.6:4143 expires=277300 Packets=3 Bytes=300 RxFlagsSeen=0x03 LastRxReport=277290 TxFlagsSeen=0x03 LastTxReport=277290 Flags=0x0013 [ RxClosing TxClosing SeenNonSyn ] RevNAT=0 SourceSecurityID=4 BackendID=0
TCP IN 10.4.34.207:43720 -> 10.4.34.6:4143 expires=277500 Packets=15 Bytes=1500 RxFlagsSeen=0x02 LastRxReport=277490 TxFlagsSeen=0x12 LastTxReport=277490 Flags=0x0012 [ SeenNonSyn ] RevNAT=0 SourceSecurityID=5 BackendID=0
TCP OUT 10.4.34.6:4143 -> 10.4.166.193:52628 expires=277365 Packets=5 Bytes=1116 RxFlagsSeen=0x12 LastRxReport=277355 TxFlagsSeen=0x02 LastTxReport=277355 Flags=0x0012 [ SeenNonSyn ] RevNAT=5 SourceSecurityID=2 BackendID=0
TCP IN 10.4.100.1:12345 -> 10.4.100.2:5432 expires=277600 Packets=20 Bytes=2000 RxFlagsSeen=0x02 LastRxReport=277590 TxFlagsSeen=0x12 LastTxReport=277590 Flags=0x0012 [ SeenNonSyn ] RevNAT=0 SourceSecurityID=6 BackendID=0
`

func portFilter(port int) Filter {
	if port == 0 {
		return Filter{}
	}
	return Filter{PortMin: port, PortMax: port}
}

func TestParseCTOutput(t *testing.T) {
	peers := ParseCTOutput(sampleCTOutput, "10.4.34.6", portFilter(4143))

	if len(peers) != 3 {
		t.Fatalf("expected 3 peers, got %d: %v", len(peers), peers)
	}

	expected := map[string]bool{
		"10.4.166.193:52628": true,
		"10.4.167.123:45120": true,
		"10.4.34.207:43720":  true,
	}
	for _, p := range peers {
		if !expected[p.Src] {
			t.Errorf("unexpected peer: %s", p.Src)
		}
		if p.DstPort != 4143 {
			t.Errorf("expected DstPort 4143, got %d for %s", p.DstPort, p.Src)
		}
	}
}

func TestParseCTOutput_ExcludesClosing(t *testing.T) {
	peers := ParseCTOutput(sampleCTOutput, "10.4.34.6", portFilter(4143))
	for _, p := range peers {
		if p.Src == "10.4.167.124:43578" {
			t.Error("should exclude RxClosing connection")
		}
	}
}

func TestParseCTOutput_ExcludesOUT(t *testing.T) {
	peers := ParseCTOutput(sampleCTOutput, "10.4.34.6", portFilter(4143))
	if len(peers) != 3 {
		t.Fatalf("expected 3 peers, got %d", len(peers))
	}
}

func TestParseCTOutput_DifferentIP(t *testing.T) {
	peers := ParseCTOutput(sampleCTOutput, "10.4.100.2", portFilter(5432))
	if len(peers) != 1 {
		t.Fatalf("expected 1 peer, got %d", len(peers))
	}
	if peers[0].Src != "10.4.100.1:12345" {
		t.Errorf("expected 10.4.100.1:12345, got %s", peers[0].Src)
	}
	if peers[0].DstPort != 5432 {
		t.Errorf("expected DstPort 5432, got %d", peers[0].DstPort)
	}
}

func TestParseCTOutput_NoMatches(t *testing.T) {
	peers := ParseCTOutput(sampleCTOutput, "10.99.99.99", portFilter(9999))
	if len(peers) != 0 {
		t.Fatalf("expected 0 peers, got %d", len(peers))
	}
}

func TestParseCTOutput_Empty(t *testing.T) {
	peers := ParseCTOutput("", "10.0.0.1", portFilter(4143))
	if len(peers) != 0 {
		t.Fatalf("expected 0 peers, got %d", len(peers))
	}
}

func TestParseCTOutput_AllPorts(t *testing.T) {
	peers := ParseCTOutput(sampleCTOutput, "10.4.34.6", Filter{})

	if len(peers) != 3 {
		t.Fatalf("expected 3 peers (all ports), got %d: %v", len(peers), peers)
	}

	for _, p := range peers {
		if p.DstPort != 4143 {
			t.Errorf("expected DstPort 4143, got %d for %s", p.DstPort, p.Src)
		}
	}

	// Also check that all-ports mode picks up connections to different ports.
	multiPortOutput := sampleCTOutput + `TCP IN 10.4.200.1:11111 -> 10.4.34.6:8080 expires=277700 RxPackets=1 RxBytes=100 RxFlagsSeen=0x02 LastRxReport=277690 TxPackets=1 TxBytes=100 TxFlagsSeen=0x12 LastTxReport=277690 Flags=0x0012 [ SeenNonSyn ] RevNAT=0 SourceSecurityID=7 IfIndex=0
`
	peers = ParseCTOutput(multiPortOutput, "10.4.34.6", Filter{})
	if len(peers) != 4 {
		t.Fatalf("expected 4 peers (multi-port), got %d: %v", len(peers), peers)
	}

	// Find the 8080 peer.
	found := false
	for _, p := range peers {
		if p.Src == "10.4.200.1:11111" {
			found = true
			if p.DstPort != 8080 {
				t.Errorf("expected DstPort 8080, got %d", p.DstPort)
			}
		}
	}
	if !found {
		t.Error("expected to find peer 10.4.200.1:11111")
	}
}

func TestParseCTOutput_PortRange(t *testing.T) {
	output := `TCP IN 10.0.0.1:1000 -> 10.1.0.1:5432 expires=100 Flags=0x0012 [ SeenNonSyn ]
TCP IN 10.0.0.2:2000 -> 10.1.0.1:5433 expires=100 Flags=0x0012 [ SeenNonSyn ]
TCP IN 10.0.0.3:3000 -> 10.1.0.1:5440 expires=100 Flags=0x0012 [ SeenNonSyn ]
TCP IN 10.0.0.4:4000 -> 10.1.0.1:6000 expires=100 Flags=0x0012 [ SeenNonSyn ]
`
	peers := ParseCTOutput(output, "10.1.0.1", Filter{PortMin: 5432, PortMax: 5440})
	if len(peers) != 3 {
		t.Fatalf("expected 3 peers in port range, got %d: %v", len(peers), peers)
	}
}

func TestParseCTOutput_StateClosing(t *testing.T) {
	peers := ParseCTOutput(sampleCTOutput, "10.4.34.6", Filter{
		PortMin: 4143, PortMax: 4143,
		States: []string{"closing"},
	})
	if len(peers) != 1 {
		t.Fatalf("expected 1 closing peer, got %d: %v", len(peers), peers)
	}
	if peers[0].Src != "10.4.167.124:43578" {
		t.Errorf("expected closing peer 10.4.167.124:43578, got %s", peers[0].Src)
	}
}

func TestParseCTOutput_StateAll(t *testing.T) {
	peers := ParseCTOutput(sampleCTOutput, "10.4.34.6", Filter{
		PortMin: 4143, PortMax: 4143,
		States: []string{"all"},
	})
	if len(peers) != 4 {
		t.Fatalf("expected 4 peers (all states), got %d: %v", len(peers), peers)
	}
}

func TestParseCTOutput_SrcCIDR(t *testing.T) {
	_, cidr, _ := net.ParseCIDR("10.4.166.0/24")
	peers := ParseCTOutput(sampleCTOutput, "10.4.34.6", Filter{
		PortMin: 4143, PortMax: 4143,
		SrcCIDR: cidr,
	})
	if len(peers) != 1 {
		t.Fatalf("expected 1 peer from 10.4.166.0/24, got %d: %v", len(peers), peers)
	}
	if peers[0].Src != "10.4.166.193:52628" {
		t.Errorf("expected 10.4.166.193:52628, got %s", peers[0].Src)
	}
}

func TestParseCTOutput_UDPProtocol(t *testing.T) {
	output := `UDP IN 10.0.0.1:1000 -> 10.1.0.1:53 expires=100 Flags=0x0000 []
TCP IN 10.0.0.2:2000 -> 10.1.0.1:53 expires=100 Flags=0x0012 [ SeenNonSyn ]
`
	peers := ParseCTOutput(output, "10.1.0.1", Filter{
		PortMin: 53, PortMax: 53,
		Protos: []string{"UDP"},
	})
	if len(peers) != 1 {
		t.Fatalf("expected 1 UDP peer, got %d: %v", len(peers), peers)
	}
	if peers[0].Src != "10.0.0.1:1000" {
		t.Errorf("expected 10.0.0.1:1000, got %s", peers[0].Src)
	}
}

func TestParseCTOutput_MultiProtocol(t *testing.T) {
	output := `UDP IN 10.0.0.1:1000 -> 10.1.0.1:53 expires=100 Flags=0x0000 []
TCP IN 10.0.0.2:2000 -> 10.1.0.1:53 expires=100 Flags=0x0012 [ SeenNonSyn ]
`
	peers := ParseCTOutput(output, "10.1.0.1", Filter{
		PortMin: 53, PortMax: 53,
		Protos: []string{"TCP", "UDP"},
	})
	if len(peers) != 2 {
		t.Fatalf("expected 2 peers (TCP+UDP), got %d: %v", len(peers), peers)
	}
}

func TestParseCTOutput_PeerFields(t *testing.T) {
	peers := ParseCTOutput(sampleCTOutput, "10.4.34.6", Filter{
		PortMin: 4143, PortMax: 4143,
		States: []string{"all"},
	})
	if len(peers) != 4 {
		t.Fatalf("expected 4 peers, got %d", len(peers))
	}

	// Find the established peer.
	var established *Peer
	for i := range peers {
		if peers[i].Src == "10.4.166.193:52628" {
			established = &peers[i]
			break
		}
	}
	if established == nil {
		t.Fatal("missing peer 10.4.166.193:52628")
	}
	if established.Proto != "TCP" {
		t.Errorf("Proto = %q, want TCP", established.Proto)
	}
	if established.State != "established" {
		t.Errorf("State = %q, want established", established.State)
	}
	// Find the closing peer.
	var closing *Peer
	for i := range peers {
		if peers[i].Src == "10.4.167.124:43578" {
			closing = &peers[i]
			break
		}
	}
	if closing == nil {
		t.Fatal("missing closing peer 10.4.167.124:43578")
	}
	if closing.State != "closing" {
		t.Errorf("State = %q, want closing", closing.State)
	}
}

func TestParseCTOutput_RichFields(t *testing.T) {
	peers := ParseCTOutput(sampleCTOutput, "10.4.34.6", Filter{
		PortMin: 4143, PortMax: 4143,
		States: []string{"all"},
	})

	// Find the first established peer.
	var p *Peer
	for i := range peers {
		if peers[i].Src == "10.4.166.193:52628" {
			p = &peers[i]
			break
		}
	}
	if p == nil {
		t.Fatal("missing peer 10.4.166.193:52628")
	}
	if p.Bytes != 452 {
		t.Errorf("Bytes = %d, want 452", p.Bytes)
	}
	if p.Packets != 5 {
		t.Errorf("Packets = %d, want 5", p.Packets)
	}
	if p.Expires != 277365 {
		t.Errorf("Expires = %d, want 277365", p.Expires)
	}
	if p.LastRxReport != 277355 {
		t.Errorf("LastRxReport = %d, want 277355", p.LastRxReport)
	}
	if p.LastTxReport != 277355 {
		t.Errorf("LastTxReport = %d, want 277355", p.LastTxReport)
	}
}

func TestParseCTOutput_SplitFieldFormat(t *testing.T) {
	// Uses RxPackets/TxPackets/RxBytes/TxBytes format (newer Cilium).
	output := `TCP IN 10.0.0.1:1000 -> 10.1.0.1:5432 expires=100 RxPackets=3 RxBytes=300 RxFlagsSeen=0x02 LastRxReport=90 TxPackets=7 TxBytes=1400 TxFlagsSeen=0x12 LastTxReport=95 Flags=0x0012 [ SeenNonSyn ] RevNAT=0 SourceSecurityID=6 IfIndex=0
`
	peers := ParseCTOutput(output, "10.1.0.1", Filter{PortMin: 5432, PortMax: 5432})
	if len(peers) != 1 {
		t.Fatalf("expected 1 peer, got %d", len(peers))
	}
	p := peers[0]
	if p.RxBytes != 300 {
		t.Errorf("RxBytes = %d, want 300", p.RxBytes)
	}
	if p.TxBytes != 1400 {
		t.Errorf("TxBytes = %d, want 1400", p.TxBytes)
	}
	if p.Bytes != 1700 {
		t.Errorf("Bytes = %d, want 1700 (300+1400)", p.Bytes)
	}
	if p.RxPackets != 3 {
		t.Errorf("RxPackets = %d, want 3", p.RxPackets)
	}
	if p.TxPackets != 7 {
		t.Errorf("TxPackets = %d, want 7", p.TxPackets)
	}
	if p.Packets != 10 {
		t.Errorf("Packets = %d, want 10 (3+7)", p.Packets)
	}
	if p.Expires != 100 {
		t.Errorf("Expires = %d, want 100", p.Expires)
	}
	if p.LastRxReport != 90 {
		t.Errorf("LastRxReport = %d, want 90", p.LastRxReport)
	}
	if p.LastTxReport != 95 {
		t.Errorf("LastTxReport = %d, want 95", p.LastTxReport)
	}
}

func TestParseCTOutput_UnderscoreFieldFormat(t *testing.T) {
	// Some Cilium versions use snake_case field names.
	output := `TCP IN 10.0.0.1:1000 -> 10.1.0.1:5432 expires=100 rx_packets=3 rx_bytes=300 RxFlagsSeen=0x02 LastRxReport=90 tx_packets=7 tx_bytes=1400 TxFlagsSeen=0x12 LastTxReport=95 Flags=0x0012 [ SeenNonSyn ] RevNAT=0 SourceSecurityID=6 IfIndex=0
`
	peers := ParseCTOutput(output, "10.1.0.1", Filter{PortMin: 5432, PortMax: 5432})
	if len(peers) != 1 {
		t.Fatalf("expected 1 peer, got %d", len(peers))
	}
	p := peers[0]
	if p.RxBytes != 300 {
		t.Errorf("RxBytes = %d, want 300", p.RxBytes)
	}
	if p.TxBytes != 1400 {
		t.Errorf("TxBytes = %d, want 1400", p.TxBytes)
	}
	if p.Bytes != 1700 {
		t.Errorf("Bytes = %d, want 1700 (300+1400)", p.Bytes)
	}
}

func TestComparePeerAddr(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"10.1.0.1:1000", "10.1.0.2:1000", -1},
		{"10.1.0.2:1000", "10.1.0.1:1000", 1},
		{"10.1.0.1:1000", "10.1.0.1:1000", 0},
		{"10.1.0.1:1000", "10.1.0.1:2000", -1},
		// Numeric vs lexicographic: 10.10.0.1 > 10.9.0.1 numerically
		{"10.9.0.1:1000", "10.10.0.1:1000", -1},
		{"10.10.0.1:1000", "10.9.0.1:1000", 1},
	}
	for _, tt := range tests {
		t.Run(tt.a+"_vs_"+tt.b, func(t *testing.T) {
			got := ComparePeerAddr(tt.a, tt.b)
			if got != tt.want {
				t.Errorf("ComparePeerAddr(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestParseCTOutput_NumericIPSort(t *testing.T) {
	output := `TCP IN 10.10.0.1:1000 -> 10.1.0.1:5432 expires=100 Flags=0x0012 [ SeenNonSyn ]
TCP IN 10.9.0.1:2000 -> 10.1.0.1:5432 expires=100 Flags=0x0012 [ SeenNonSyn ]
TCP IN 10.1.0.1:3000 -> 10.1.0.1:5432 expires=100 Flags=0x0012 [ SeenNonSyn ]
`
	peers := ParseCTOutput(output, "10.1.0.1", Filter{PortMin: 5432, PortMax: 5432})
	if len(peers) != 3 {
		t.Fatalf("expected 3 peers, got %d", len(peers))
	}
	// Should be sorted numerically: 10.1.0.1, 10.9.0.1, 10.10.0.1
	if peers[0].Src != "10.1.0.1:3000" {
		t.Errorf("peers[0] = %s, want 10.1.0.1:3000", peers[0].Src)
	}
	if peers[1].Src != "10.9.0.1:2000" {
		t.Errorf("peers[1] = %s, want 10.9.0.1:2000", peers[1].Src)
	}
	if peers[2].Src != "10.10.0.1:1000" {
		t.Errorf("peers[2] = %s, want 10.10.0.1:1000", peers[2].Src)
	}
}

func TestNewFilter(t *testing.T) {
	tests := []struct {
		name    string
		opts    FilterOpts
		wantErr bool
		check   func(t *testing.T, f Filter)
	}{
		{
			name: "single port",
			opts: FilterOpts{Port: "5432"},
			check: func(t *testing.T, f Filter) {
				if f.PortMin != 5432 || f.PortMax != 5432 {
					t.Errorf("port = %d-%d, want 5432-5432", f.PortMin, f.PortMax)
				}
			},
		},
		{
			name: "port range",
			opts: FilterOpts{Port: "5432-5440"},
			check: func(t *testing.T, f Filter) {
				if f.PortMin != 5432 || f.PortMax != 5440 {
					t.Errorf("port = %d-%d, want 5432-5440", f.PortMin, f.PortMax)
				}
			},
		},
		{
			name:    "invalid port",
			opts:    FilterOpts{Port: "abc"},
			wantErr: true,
		},
		{
			name:    "invalid port range",
			opts:    FilterOpts{Port: "abc-def"},
			wantErr: true,
		},
		{
			name: "multi protocol",
			opts: FilterOpts{Proto: "tcp,udp"},
			check: func(t *testing.T, f Filter) {
				if len(f.Protos) != 2 || f.Protos[0] != "TCP" || f.Protos[1] != "UDP" {
					t.Errorf("protos = %v, want [TCP UDP]", f.Protos)
				}
			},
		},
		{
			name: "source IP without CIDR",
			opts: FilterOpts{Src: "10.0.0.1"},
			check: func(t *testing.T, f Filter) {
				if f.SrcCIDR == nil {
					t.Fatal("SrcCIDR should not be nil")
				}
				if f.SrcCIDR.String() != "10.0.0.1/32" {
					t.Errorf("SrcCIDR = %s, want 10.0.0.1/32", f.SrcCIDR)
				}
			},
		},
		{
			name:    "invalid CIDR",
			opts:    FilterOpts{Src: "not-an-ip"},
			wantErr: true,
		},
		{
			name: "default proto and state",
			opts: FilterOpts{},
			check: func(t *testing.T, f Filter) {
				if len(f.Protos) != 1 || f.Protos[0] != "TCP" {
					t.Errorf("protos = %v, want [TCP]", f.Protos)
				}
				if len(f.States) != 1 || f.States[0] != "established" {
					t.Errorf("states = %v, want [established]", f.States)
				}
			},
		},
		{
			name:    "port range reversed",
			opts:    FilterOpts{Port: "5440-5432"},
			wantErr: true,
		},
		{
			name:    "port too high",
			opts:    FilterOpts{Port: "99999"},
			wantErr: true,
		},
		{
			name:    "port zero",
			opts:    FilterOpts{Port: "0"},
			wantErr: true,
		},
		{
			name:    "port range high bound too high",
			opts:    FilterOpts{Port: "5432-70000"},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := NewFilter(tt.opts)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.check != nil {
				tt.check(t, f)
			}
		})
	}
}

func TestFilterSummary(t *testing.T) {
	tests := []struct {
		name   string
		filter Filter
		want   string
	}{
		{"default", Filter{}, "all ports"},
		{"single port", Filter{PortMin: 5432, PortMax: 5432}, ":5432"},
		{"port range", Filter{PortMin: 5432, PortMax: 5440}, ":5432-5440"},
		{"udp", Filter{Protos: []string{"UDP"}}, "all ports  udp"},
		{"multi proto", Filter{PortMin: 53, PortMax: 53, Protos: []string{"TCP", "UDP"}}, ":53  tcp+udp"},
		{"state all", Filter{States: []string{"all"}}, "all ports  state:all"},
		{"src cidr", Filter{SrcCIDR: func() *net.IPNet { _, n, _ := net.ParseCIDR("10.0.0.0/24"); return n }()}, "all ports  src:10.0.0.0/24"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.filter.FilterSummary()
			if got != tt.want {
				t.Errorf("FilterSummary() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestComparePeerAddr_UnparseableIPs(t *testing.T) {
	// Both unparseable: falls back to string comparison.
	if got := ComparePeerAddr("zzz:1000", "aaa:1000"); got != 1 {
		t.Errorf("expected 1 for zzz > aaa, got %d", got)
	}
	if got := ComparePeerAddr("aaa:1000", "zzz:1000"); got != -1 {
		t.Errorf("expected -1 for aaa < zzz, got %d", got)
	}
	if got := ComparePeerAddr("aaa:1000", "aaa:1000"); got != 0 {
		t.Errorf("expected 0 for equal, got %d", got)
	}
}

func TestSplitHostPort_MissingPort(t *testing.T) {
	// No colon at all: returns full string as host, port 0.
	if got := ComparePeerAddr("10.0.0.1", "10.0.0.2"); got != -1 {
		t.Errorf("expected -1 for addresses without ports, got %d", got)
	}
}
