package cilium

import "testing"

const sampleCTOutput = `TCP IN 10.4.166.193:52628 -> 10.4.34.6:4143 expires=277365 RxPackets=5 RxBytes=452 RxFlagsSeen=0x02 LastRxReport=277355 TxPackets=5 TxBytes=1116 TxFlagsSeen=0x12 LastTxReport=277355 Flags=0x0012 [ SeenNonSyn ] RevNAT=0 SourceSecurityID=2 IfIndex=0
TCP IN 10.4.167.123:45120 -> 10.4.34.6:4143 expires=277400 RxPackets=10 RxBytes=900 RxFlagsSeen=0x02 LastRxReport=277390 TxPackets=8 TxBytes=2000 TxFlagsSeen=0x12 LastTxReport=277390 Flags=0x0012 [ SeenNonSyn ] RevNAT=0 SourceSecurityID=3 IfIndex=0
TCP IN 10.4.167.124:43578 -> 10.4.34.6:4143 expires=277300 RxPackets=3 RxBytes=300 RxFlagsSeen=0x03 LastRxReport=277290 TxPackets=2 TxBytes=200 TxFlagsSeen=0x03 LastTxReport=277290 Flags=0x0013 [ RxClosing TxClosing SeenNonSyn ] RevNAT=0 SourceSecurityID=4 IfIndex=0
TCP IN 10.4.34.207:43720 -> 10.4.34.6:4143 expires=277500 RxPackets=15 RxBytes=1500 RxFlagsSeen=0x02 LastRxReport=277490 TxPackets=12 TxBytes=3000 TxFlagsSeen=0x12 LastTxReport=277490 Flags=0x0012 [ SeenNonSyn ] RevNAT=0 SourceSecurityID=5 IfIndex=0
TCP OUT 10.4.34.6:4143 -> 10.4.166.193:52628 expires=277365 RxPackets=5 RxBytes=1116 RxFlagsSeen=0x12 LastRxReport=277355 TxPackets=5 TxBytes=452 TxFlagsSeen=0x02 LastTxReport=277355 Flags=0x0012 [ SeenNonSyn ] RevNAT=5 SourceSecurityID=2 IfIndex=0
TCP IN 10.4.100.1:12345 -> 10.4.100.2:5432 expires=277600 RxPackets=20 RxBytes=2000 RxFlagsSeen=0x02 LastRxReport=277590 TxPackets=18 TxBytes=4000 TxFlagsSeen=0x12 LastTxReport=277590 Flags=0x0012 [ SeenNonSyn ] RevNAT=0 SourceSecurityID=6 IfIndex=0
`

func TestParseCTOutput(t *testing.T) {
	peers := ParseCTOutput(sampleCTOutput, "10.4.34.6", 4143)

	if len(peers) != 3 {
		t.Fatalf("expected 3 peers, got %d: %v", len(peers), peers)
	}

	expected := map[string]bool{
		"10.4.166.193:52628": true,
		"10.4.167.123:45120": true,
		"10.4.34.207:43720":  true,
	}
	for _, p := range peers {
		if !expected[p] {
			t.Errorf("unexpected peer: %s", p)
		}
	}
}

func TestParseCTOutput_ExcludesClosing(t *testing.T) {
	peers := ParseCTOutput(sampleCTOutput, "10.4.34.6", 4143)
	for _, p := range peers {
		if p == "10.4.167.124:43578" {
			t.Error("should exclude RxClosing connection")
		}
	}
}

func TestParseCTOutput_ExcludesOUT(t *testing.T) {
	peers := ParseCTOutput(sampleCTOutput, "10.4.34.6", 4143)
	if len(peers) != 3 {
		t.Fatalf("expected 3 peers, got %d", len(peers))
	}
}

func TestParseCTOutput_DifferentIP(t *testing.T) {
	peers := ParseCTOutput(sampleCTOutput, "10.4.100.2", 5432)
	if len(peers) != 1 {
		t.Fatalf("expected 1 peer, got %d", len(peers))
	}
	if peers[0] != "10.4.100.1:12345" {
		t.Errorf("expected 10.4.100.1:12345, got %s", peers[0])
	}
}

func TestParseCTOutput_NoMatches(t *testing.T) {
	peers := ParseCTOutput(sampleCTOutput, "10.99.99.99", 9999)
	if len(peers) != 0 {
		t.Fatalf("expected 0 peers, got %d", len(peers))
	}
}

func TestParseCTOutput_Empty(t *testing.T) {
	peers := ParseCTOutput("", "10.0.0.1", 4143)
	if len(peers) != 0 {
		t.Fatalf("expected 0 peers, got %d", len(peers))
	}
}
