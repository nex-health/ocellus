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
	TupleKey6 *tupleKey6 `json:"TupleKey6,omitempty"`
}

type tupleKey6 struct {
	DestAddr   string `json:"DestAddr"`   // base64-encoded 16-byte IPv6
	SourceAddr string `json:"SourceAddr"` // base64-encoded 16-byte IPv6
	DestPort   uint16 `json:"DestPort"`
	SourcePort uint16 `json:"SourcePort"`
	NextHeader uint8  `json:"NextHeader"`
	Flags      uint8  `json:"Flags"`
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

func decodeIPv6(b64 string) (net.IP, error) {
	data, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(data) != 16 {
		return nil, fmt.Errorf("invalid IPv6: %s", b64)
	}
	ip := make(net.IP, 16)
	copy(ip, data)
	return ip, nil
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

// parsedKey holds the extracted fields from either a TupleKey4 or TupleKey6.
type parsedKey struct {
	isIn      bool
	proto     string
	podIP     net.IP
	peerIP    net.IP
	dstPort   int // ntohs(DestPort)
	peerPort  int
	ipVersion string // "4" or "6"
}

// tupleFields holds the common fields shared by TupleKey4 and TupleKey6.
type tupleFields struct {
	DestAddr   string
	SourceAddr string
	DestPort   uint16
	SourcePort uint16
	NextHeader uint8
	Flags      uint8
}

type ipDecoder func(string) (net.IP, error)

// parseKey extracts fields from a tuple key using the given IP decoder and version.
func parseKey(tf tupleFields, decode ipDecoder, ipVersion string) (*parsedKey, error) {
	isIn := tf.Flags&0x01 != 0

	var proto string
	switch tf.NextHeader {
	case 6:
		proto = "TCP"
	case 17:
		proto = "UDP"
	default:
		return nil, fmt.Errorf("unsupported protocol %d", tf.NextHeader)
	}

	var podIPField, peerIPField string
	var peerPortField uint16
	if isIn {
		podIPField = tf.DestAddr
		peerIPField = tf.SourceAddr
		peerPortField = tf.SourcePort
	} else {
		podIPField = tf.SourceAddr
		peerIPField = tf.DestAddr
		peerPortField = tf.DestPort
	}

	podIP, err := decode(podIPField)
	if err != nil {
		return nil, err
	}

	peerIP, err := decode(peerIPField)
	if err != nil {
		return nil, err
	}

	return &parsedKey{
		isIn:      isIn,
		proto:     proto,
		podIP:     podIP,
		peerIP:    peerIP,
		dstPort:   int(ntohs(tf.DestPort)),
		peerPort:  int(ntohs(peerPortField)),
		ipVersion: ipVersion,
	}, nil
}

func parseKey4(k *tupleKey4) (*parsedKey, error) {
	return parseKey(tupleFields{
		DestAddr: k.DestAddr, SourceAddr: k.SourceAddr,
		DestPort: k.DestPort, SourcePort: k.SourcePort,
		NextHeader: k.NextHeader, Flags: k.Flags,
	}, decodeIPv4, "4")
}

func parseKey6(k *tupleKey6) (*parsedKey, error) {
	return parseKey(tupleFields{
		DestAddr: k.DestAddr, SourceAddr: k.SourceAddr,
		DestPort: k.DestPort, SourcePort: k.SourcePort,
		NextHeader: k.NextHeader, Flags: k.Flags,
	}, decodeIPv6, "6")
}

// ParseJSONCTOutput parses the JSON output of "cilium bpf ct list global -o json"
// and returns unique peers matching the filter for the given podIP.
func ParseJSONCTOutput(data string, podIP string, filter Filter) ([]Peer, error) {
	var records []ctMapRecord
	if err := json.Unmarshal([]byte(data), &records); err != nil {
		return nil, fmt.Errorf("parse JSON CT output: %w", err)
	}

	ff := newFilterFlags(filter)
	protos := filter.effectiveProtos()

	seen := make(map[string]bool)
	var peers []Peer

	for _, rec := range records {
		var pk *parsedKey
		var err error
		switch {
		case rec.Key.TupleKey4 != nil:
			if !ff.wantV4 {
				continue
			}
			pk, err = parseKey4(rec.Key.TupleKey4)
		case rec.Key.TupleKey6 != nil:
			if !ff.wantV6 {
				continue
			}
			pk, err = parseKey6(rec.Key.TupleKey6)
		default:
			continue
		}
		if err != nil {
			continue
		}

		// Direction filter.
		if pk.isIn && !ff.dirIn {
			continue
		}
		if !pk.isIn && !ff.dirOut {
			continue
		}

		if !slices.Contains(protos, pk.proto) {
			continue
		}

		if pk.podIP.String() != podIP {
			continue
		}

		if !filter.matchPort(pk.dstPort) {
			continue
		}

		if filter.SrcCIDR != nil && !filter.SrcCIDR.Contains(pk.peerIP) {
			continue
		}

		// State detection from Flags field bits.
		// Bit 0 = RxClosing, Bit 1 = TxClosing.
		ctFlags := rec.Value.Flags
		isClosing := ctFlags&0x0001 != 0 || ctFlags&0x0002 != 0

		if !ff.matchState(isClosing) {
			continue
		}

		peerAddr := formatAddrPort(pk.peerIP.String(), pk.peerPort)

		direction := "in"
		if !pk.isIn {
			direction = "out"
		}

		// Dedup key includes direction when showing both.
		dedupKey := peerAddr
		if ff.dirIn && ff.dirOut {
			dedupKey = direction + ":" + peerAddr
		}
		if seen[dedupKey] {
			continue
		}
		seen[dedupKey] = true

		state := "established"
		if isClosing {
			state = "closing"
		}

		// RxPackets/RxBytes stored in Union0 for non-NAT entries.
		rxPackets := rec.Value.Union0[0]
		rxBytes := rec.Value.Union0[1]

		peers = append(peers, Peer{
			Src:          peerAddr,
			DstPort:      pk.dstPort,
			Proto:        pk.proto,
			State:        state,
			Direction:    direction,
			IPVersion:    pk.ipVersion,
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
