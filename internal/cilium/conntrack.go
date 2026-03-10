package cilium

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
)

// Peer represents a conntrack peer with its source address and the destination
// port on the pod it is connected to.
type Peer struct {
	Src          string `json:"src"`        // e.g. "10.4.166.193:52628" or "[f00d::1]:52628"
	DstPort      int    `json:"dst_port"`   // destination port on the pod
	Proto        string `json:"proto"`      // "TCP" or "UDP"
	State        string `json:"state"`      // "established" or "closing"
	Direction    string `json:"direction"`  // "in" or "out"
	IPVersion    string `json:"ip_version"` // "4" or "6"
	Bytes        uint64 `json:"bytes"`      // total bytes (RxBytes+TxBytes or Bytes)
	Packets      uint64 `json:"packets"`    // total packets (RxPackets+TxPackets or Packets)
	RxBytes      uint64 `json:"rx_bytes"`
	TxBytes      uint64 `json:"tx_bytes"`
	RxPackets    uint64 `json:"rx_packets"`
	TxPackets    uint64 `json:"tx_packets"`
	Expires      uint32 `json:"expires"` // kernel time until GC (ms)
	LastRxReport uint32 `json:"last_rx_report"`
	LastTxReport uint32 `json:"last_tx_report"`
	RxFlagsSeen  uint8  `json:"rx_flags_seen"`
	TxFlagsSeen  uint8  `json:"tx_flags_seen"`
}

// parseKVUint extracts a uint64 value for a key like "Bytes=452" from the line.
// Returns 0 if the key is not found or the value cannot be parsed. This is
// intentional: missing or malformed fields default to zero rather than causing
// parse failures, since different Cilium versions emit different field sets.
func parseKVUint(line, key string) uint64 {
	prefix := key + "="
	idx := strings.Index(line, prefix)
	if idx < 0 {
		return 0
	}
	start := idx + len(prefix)
	end := start
	for end < len(line) && line[end] != ' ' && line[end] != '\t' {
		end++
	}
	v, _ := strconv.ParseUint(line[start:end], 10, 64)
	return v
}

// parseKVHex extracts a uint8 from a hex value like "RxFlagsSeen=0x02".
func parseKVHex(line, key string) uint8 {
	prefix := key + "="
	idx := strings.Index(line, prefix)
	if idx < 0 {
		return 0
	}
	start := idx + len(prefix)
	end := start
	for end < len(line) && line[end] != ' ' && line[end] != '\t' {
		end++
	}
	v, _ := strconv.ParseUint(strings.TrimPrefix(line[start:end], "0x"), 16, 8)
	return uint8(v)
}

// splitAddrPort splits an address string into host and port.
// Handles both IPv4 "ip:port" and IPv6 "[ip]:port" formats.
func splitAddrPort(addr string) (string, int) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return addr, 0
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return host, 0
	}
	return host, port
}

// formatAddrPort formats a host:port pair. IPv6 addresses are bracketed.
func formatAddrPort(host string, port int) string {
	ip := net.ParseIP(host)
	if ip != nil && ip.To4() == nil {
		return fmt.Sprintf("[%s]:%d", host, port)
	}
	return fmt.Sprintf("%s:%d", host, port)
}

// dirPrefix pairs a line prefix string with its direction.
type dirPrefix struct {
	prefix string
	isOut  bool
}

func buildDirPrefixes(protos []string, ff filterFlags) []dirPrefix {
	var prefixes []dirPrefix
	for _, p := range protos {
		if ff.dirIn {
			prefixes = append(prefixes, dirPrefix{p + " IN ", false})
		}
		if ff.dirOut {
			prefixes = append(prefixes, dirPrefix{p + " OUT ", true})
		}
	}
	return prefixes
}

// parseSplitOrCombined extracts rx/tx counter values, falling back to a
// combined field for older Cilium versions.
func parseSplitOrCombined(line, rxKey, rxKeyLower, txKey, txKeyLower, totalKey, totalKeyLower string) (rx, tx uint64) {
	rx = parseKVUint(line, rxKey)
	if rx == 0 {
		rx = parseKVUint(line, rxKeyLower)
	}
	tx = parseKVUint(line, txKey)
	if tx == 0 {
		tx = parseKVUint(line, txKeyLower)
	}
	if rx == 0 && tx == 0 {
		total := parseKVUint(line, totalKey)
		if total == 0 {
			total = parseKVUint(line, totalKeyLower)
		}
		rx = total
	}
	return rx, tx
}

func parseSplitOrCombinedBytes(line string) (rx, tx uint64) {
	return parseSplitOrCombined(line, "RxBytes", "rx_bytes", "TxBytes", "tx_bytes", "Bytes", "bytes")
}

func parseSplitOrCombinedPackets(line string) (rx, tx uint64) {
	return parseSplitOrCombined(line, "RxPackets", "rx_packets", "TxPackets", "tx_packets", "Packets", "packets")
}

// parseCTLine attempts to parse a single conntrack line and returns a Peer
// if it matches the filter, or nil if it should be skipped.
func parseCTLine(line, podIP string, filter Filter, ff filterFlags, prefixes []dirPrefix) *Peer {
	// 1. Protocol + direction prefix.
	matchedProto := false
	isOutDir := false
	for _, pfx := range prefixes {
		if strings.HasPrefix(line, pfx.prefix) {
			matchedProto = true
			isOutDir = pfx.isOut
			break
		}
	}
	if !matchedProto {
		return nil
	}

	// 2. Extract fields.
	fields := strings.Fields(line)
	if len(fields) < 5 {
		return nil
	}

	var podAddr, peerAddr string
	if isOutDir {
		podAddr = fields[2]
		peerAddr = fields[4]
	} else {
		podAddr = fields[4]
		peerAddr = fields[2]
	}

	// 3. Pod IP match.
	podIPv4Prefix := podIP + ":"
	podIPv6Prefix := "[" + podIP + "]:"
	if !strings.HasPrefix(podAddr, podIPv4Prefix) && !strings.HasPrefix(podAddr, podIPv6Prefix) {
		return nil
	}

	// 4. IP version filter.
	isV6 := strings.HasPrefix(peerAddr, "[")
	if (isV6 && !ff.wantV6) || (!isV6 && !ff.wantV4) {
		return nil
	}

	// 5. State.
	isClosing := strings.Contains(line, "RxClosing") || strings.Contains(line, "TxClosing")
	if !ff.matchState(isClosing) {
		return nil
	}

	// 6. Port filter.
	_, dstPort := splitAddrPort(fields[4])
	if !filter.matchPort(dstPort) {
		return nil
	}

	// 7. Source CIDR.
	if filter.SrcCIDR != nil {
		srcHost, _ := splitAddrPort(peerAddr)
		srcIP := net.ParseIP(srcHost)
		if srcIP == nil || !filter.SrcCIDR.Contains(srcIP) {
			return nil
		}
	}

	// Build peer.
	state := StateEstablished
	if isClosing {
		state = StateClosing
	}
	direction := DirIn
	if isOutDir {
		direction = DirOut
	}
	ipVersion := "4"
	if isV6 {
		ipVersion = "6"
	}

	rxBytes, txBytes := parseSplitOrCombinedBytes(line)
	rxPackets, txPackets := parseSplitOrCombinedPackets(line)

	return &Peer{
		Src:          peerAddr,
		DstPort:      dstPort,
		Proto:        fields[0],
		State:        state,
		Direction:    direction,
		IPVersion:    ipVersion,
		RxBytes:      rxBytes,
		TxBytes:      txBytes,
		RxPackets:    rxPackets,
		TxPackets:    txPackets,
		Bytes:        rxBytes + txBytes,
		Packets:      rxPackets + txPackets,
		Expires:      uint32(parseKVUint(line, "expires")),
		LastRxReport: uint32(parseKVUint(line, "LastRxReport")),
		LastTxReport: uint32(parseKVUint(line, "LastTxReport")),
		RxFlagsSeen:  parseKVHex(line, "RxFlagsSeen"),
		TxFlagsSeen:  parseKVHex(line, "TxFlagsSeen"),
	}
}

// ParseCTOutput parses cilium bpf ct list output and returns unique peers
// matching the filter for the given podIP.
func ParseCTOutput(output string, podIP string, filter Filter) []Peer {
	ff := newFilterFlags(filter)
	prefixes := buildDirPrefixes(filter.effectiveProtos(), ff)

	seen := make(map[string]bool)
	var peers []Peer

	for line := range strings.SplitSeq(output, "\n") {
		peer := parseCTLine(line, podIP, filter, ff, prefixes)
		if key := dedupPeer(peer, ff, seen); key != "" {
			seen[key] = true
			peers = append(peers, *peer)
		}
	}

	sort.Slice(peers, func(i, j int) bool {
		return ComparePeerAddr(peers[i].Src, peers[j].Src) < 0
	})
	return peers
}

// ComparePeerAddr compares two "ip:port" or "[ipv6]:port" address strings numerically.
// Returns -1, 0, or 1 like strings.Compare but using numeric IP/port ordering.
func ComparePeerAddr(a, b string) int {
	aIP, aPort := splitHostPortCompare(a)
	bIP, bPort := splitHostPortCompare(b)

	if cmp := compareIP(aIP, bIP); cmp != 0 {
		return cmp
	}
	if aPort < bPort {
		return -1
	}
	if aPort > bPort {
		return 1
	}
	return 0
}

func splitHostPortCompare(addr string) (string, int) {
	host, portStr, err := net.SplitHostPort(addr)
	if err == nil {
		port, err := strconv.Atoi(portStr)
		if err == nil {
			return host, port
		}
		return host, 0
	}
	return addr, 0
}

func compareIP(a, b string) int {
	aIP := net.ParseIP(a)
	bIP := net.ParseIP(b)
	if aIP == nil || bIP == nil {
		return strings.Compare(a, b)
	}
	return strings.Compare(string(aIP.To16()), string(bIP.To16()))
}
