package cilium

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"slices"
	"sort"
)

type ctMapRecord struct {
	Key   ctKey   `json:"Key"`
	Value ctValue `json:"Value"`
}

type ctKey struct {
	TupleKey4 *tupleKey4 `json:"TupleKey4,omitempty"`
}

type tupleKey4 struct {
	DestAddr   string `json:"DestAddr"`
	SourceAddr string `json:"SourceAddr"`
	DestPort   uint16 `json:"DestPort"`
	SourcePort uint16 `json:"SourcePort"`
	NextHeader uint8  `json:"NextHeader"`
	Flags      uint8  `json:"Flags"`
}

type ctValue struct {
	Union0           [2]uint64 `json:"Union0"`
	Packets          uint64    `json:"Packets"`
	Bytes            uint64    `json:"Bytes"`
	Lifetime         uint32    `json:"Lifetime"`
	Flags            uint16    `json:"Flags"`
	RevNAT           uint16    `json:"RevNAT"`
	TxFlagsSeen      uint8     `json:"TxFlagsSeen"`
	RxFlagsSeen      uint8     `json:"RxFlagsSeen"`
	SourceSecurityID uint32    `json:"SourceSecurityID"`
	LastTxReport     uint32    `json:"LastTxReport"`
	LastRxReport     uint32    `json:"LastRxReport"`
}

func decodeIPv4(b64 string) (net.IP, error) {
	data, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(data) != 4 {
		return nil, fmt.Errorf("invalid IPv4: %s", b64)
	}
	return net.IPv4(data[0], data[1], data[2], data[3]), nil
}

// ntohs converts a network byte order (big-endian) port to host byte order.
// This assumes a little-endian host, which is true for all supported Go
// platforms (amd64, arm64). On a hypothetical big-endian host this would
// produce incorrect results.
func ntohs(port uint16) uint16 {
	buf := make([]byte, 2)
	binary.LittleEndian.PutUint16(buf, port)
	return binary.BigEndian.Uint16(buf)
}

// ParseJSONCTOutput parses the JSON output of "cilium bpf ct list global -o json"
// and returns unique peers with active IN connections to the given podIP matching
// the filter.
func ParseJSONCTOutput(data string, podIP string, filter Filter) ([]Peer, error) {
	var records []ctMapRecord
	if err := json.Unmarshal([]byte(data), &records); err != nil {
		return nil, fmt.Errorf("parse JSON CT output: %w", err)
	}

	protos := filter.effectiveProtos()
	states := filter.effectiveStates()
	stateAll := false
	stateClosing := false
	stateEstablished := false
	for _, s := range states {
		switch s {
		case "all":
			stateAll = true
		case "closing":
			stateClosing = true
		case "established":
			stateEstablished = true
		}
	}

	seen := make(map[string]bool)
	var peers []Peer

	for _, rec := range records {
		k := rec.Key.TupleKey4
		if k == nil {
			continue
		}

		// TUPLE_F_IN (bit 0) means IN direction in Cilium's CT map.
		// Other bits may be set (e.g. TUPLE_F_SERVICE=4), so check the bit.
		if k.Flags&0x01 == 0 {
			continue
		}

		var proto string
		switch k.NextHeader {
		case 6:
			proto = "TCP"
		case 17:
			proto = "UDP"
		default:
			continue
		}
		matchedProto := slices.Contains(protos, proto)
		if !matchedProto {
			continue
		}

		dstIP, err := decodeIPv4(k.DestAddr)
		if err != nil {
			continue
		}
		if dstIP.String() != podIP {
			continue
		}

		dstPort := int(ntohs(k.DestPort))
		if filter.PortMin > 0 || filter.PortMax > 0 {
			lo := filter.PortMin
			hi := filter.PortMax
			if lo == 0 {
				lo = 1
			}
			if hi == 0 {
				hi = 65535
			}
			if dstPort < lo || dstPort > hi {
				continue
			}
		}

		srcIP, err := decodeIPv4(k.SourceAddr)
		if err != nil {
			continue
		}
		if filter.SrcCIDR != nil && !filter.SrcCIDR.Contains(srcIP) {
			continue
		}

		// State detection from Flags field bits.
		// Bit 0 = RxClosing, Bit 1 = TxClosing.
		ctFlags := rec.Value.Flags
		isClosing := ctFlags&0x0001 != 0 || ctFlags&0x0002 != 0

		if !stateAll {
			if stateEstablished && !stateClosing && isClosing {
				continue
			}
			if stateClosing && !stateEstablished && !isClosing {
				continue
			}
		}

		srcPort := int(ntohs(k.SourcePort))
		srcAddr := fmt.Sprintf("%s:%d", srcIP.String(), srcPort)
		if seen[srcAddr] {
			continue
		}
		seen[srcAddr] = true

		state := "established"
		if isClosing {
			state = "closing"
		}

		// RxPackets/RxBytes stored in Union0 for non-NAT entries.
		rxPackets := rec.Value.Union0[0]
		rxBytes := rec.Value.Union0[1]

		peers = append(peers, Peer{
			Src:          srcAddr,
			DstPort:      dstPort,
			Proto:        proto,
			State:        state,
			RxBytes:      rxBytes,
			TxBytes:      rec.Value.Bytes,
			RxPackets:    rxPackets,
			TxPackets:    rec.Value.Packets,
			Bytes:        rxBytes + rec.Value.Bytes,
			Packets:      rxPackets + rec.Value.Packets,
			Expires:      rec.Value.Lifetime,
			LastRxReport: rec.Value.LastRxReport,
			LastTxReport: rec.Value.LastTxReport,
			RxFlagsSeen:  rec.Value.RxFlagsSeen,
			TxFlagsSeen:  rec.Value.TxFlagsSeen,
		})
	}

	sort.Slice(peers, func(i, j int) bool {
		return ComparePeerAddr(peers[i].Src, peers[j].Src) < 0
	})
	return peers, nil
}

// QueryNodeJSON execs into the Cilium agent and returns raw JSON CT output.
func QueryNodeJSON(ctx context.Context, client PodExecer, ciliumPod string) (string, error) {
	output, err := client.Exec(ctx, "kube-system", ciliumPod, "cilium-agent", []string{
		"cilium", "bpf", "ct", "list", "global", "-o", "json",
	})
	if err != nil {
		return "", fmt.Errorf("exec into %s (json): %w", ciliumPod, err)
	}
	return output, nil
}

// JSONSource queries conntrack using the JSON CLI output for structured parsing.
type JSONSource struct{}

func (s *JSONSource) QueryPeers(ctx context.Context, client PodExecer, ciliumPod string, podIPs []string, filter Filter) (map[string][]Peer, error) {
	output, err := QueryNodeJSON(ctx, client, ciliumPod)
	if err != nil {
		return nil, err
	}
	results := make(map[string][]Peer, len(podIPs))
	for _, ip := range podIPs {
		peers, err := ParseJSONCTOutput(output, ip, filter)
		if err != nil {
			return nil, err
		}
		results[ip] = peers
	}
	return results, nil
}
