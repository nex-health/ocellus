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

// Filter controls which conntrack entries are included.
type Filter struct {
	PortMin    int        // 0 = no lower bound
	PortMax    int        // 0 = no upper bound; both 0 = all ports
	Protos     []string   // e.g. ["TCP", "UDP"]; empty = ["TCP"]
	SrcCIDR    *net.IPNet // nil = no source filter
	States     []string   // "established", "closing", "all"; empty = ["established"]
	Directions []string   // e.g. ["in"], ["out"], ["in","out"]; empty = ["in","out"]
	IPVersions []string   // e.g. ["4"], ["6"], ["4","6"]; empty = ["4","6"]
}

// FilterOpts holds raw string options for building a Filter.
type FilterOpts struct {
	Port      string // e.g. "5432", "5432-5440", or ""
	Proto     string // e.g. "tcp", "udp", "tcp,udp"
	Src       string // e.g. "10.4.166.0/24", "10.0.0.1", or ""
	State     string // e.g. "established", "closing", "all"
	Direction string // e.g. "in", "out", "all"
	IPVersion string // e.g. "4", "6", "all"
}

// NewFilter creates a Filter from string options, returning an error if any
// option is invalid.
func NewFilter(opts FilterOpts) (Filter, error) {
	var f Filter

	// Parse port.
	if opts.Port != "" {
		if idx := strings.Index(opts.Port, "-"); idx >= 0 {
			lo, err := strconv.Atoi(opts.Port[:idx])
			if err != nil {
				return f, fmt.Errorf("invalid port range: %s", opts.Port)
			}
			hi, err := strconv.Atoi(opts.Port[idx+1:])
			if err != nil {
				return f, fmt.Errorf("invalid port range: %s", opts.Port)
			}
			if lo < 1 || lo > 65535 || hi < 1 || hi > 65535 {
				return f, fmt.Errorf("invalid port range %s: ports must be 1-65535", opts.Port)
			}
			if lo > hi {
				return f, fmt.Errorf("invalid port range %d-%d: min must be <= max", lo, hi)
			}
			f.PortMin = lo
			f.PortMax = hi
		} else {
			p, err := strconv.Atoi(opts.Port)
			if err != nil {
				return f, fmt.Errorf("invalid port: %s", opts.Port)
			}
			if p < 1 || p > 65535 {
				return f, fmt.Errorf("invalid port %d: must be 1-65535", p)
			}
			f.PortMin = p
			f.PortMax = p
		}
	}

	// Parse protocol.
	proto := opts.Proto
	if proto == "" {
		proto = "tcp,udp"
	}
	for p := range strings.SplitSeq(proto, ",") {
		p = strings.ToUpper(strings.TrimSpace(p))
		if p != "" {
			f.Protos = append(f.Protos, p)
		}
	}

	// Validate protocols.
	for _, p := range f.Protos {
		if p != "TCP" && p != "UDP" {
			return f, fmt.Errorf("unsupported protocol %q (valid: tcp, udp)", strings.ToLower(p))
		}
	}

	// Parse source CIDR.
	if opts.Src != "" {
		cidrStr := opts.Src
		if !strings.Contains(cidrStr, "/") {
			cidrStr += "/32"
		}
		_, cidr, err := net.ParseCIDR(cidrStr)
		if err != nil {
			return f, fmt.Errorf("invalid source CIDR: %s", opts.Src)
		}
		f.SrcCIDR = cidr
	}

	// Parse state.
	state := opts.State
	if state == "" {
		state = "established"
	}
	for s := range strings.SplitSeq(state, ",") {
		s = strings.ToLower(strings.TrimSpace(s))
		if s != "" {
			f.States = append(f.States, s)
		}
	}

	// Parse direction.
	dir := strings.ToLower(strings.TrimSpace(opts.Direction))
	if dir == "" {
		dir = "all"
	}
	switch dir {
	case "in":
		f.Directions = []string{"in"}
	case "out":
		f.Directions = []string{"out"}
	case "all":
		f.Directions = []string{"in", "out"}
	default:
		return f, fmt.Errorf("invalid direction %q (valid: in, out, all)", dir)
	}

	// Parse IP version.
	ipv := strings.TrimSpace(opts.IPVersion)
	if ipv == "" {
		ipv = "all"
	}
	switch ipv {
	case "4":
		f.IPVersions = []string{"4"}
	case "6":
		f.IPVersions = []string{"6"}
	case "all":
		f.IPVersions = []string{"4", "6"}
	default:
		return f, fmt.Errorf("invalid IP version %q (valid: 4, 6, all)", ipv)
	}

	return f, nil
}

// FilterSummary returns a human-readable summary of the filter for display.
func (f Filter) FilterSummary() string {
	var parts []string

	// Port.
	switch {
	case f.PortMin > 0 && f.PortMin == f.PortMax:
		parts = append(parts, fmt.Sprintf(":%d", f.PortMin))
	case f.PortMin > 0 || f.PortMax > 0:
		lo := f.PortMin
		if lo == 0 {
			lo = 1
		}
		hi := f.PortMax
		if hi == 0 {
			hi = 65535
		}
		parts = append(parts, fmt.Sprintf(":%d-%d", lo, hi))
	default:
		parts = append(parts, "all ports")
	}

	// Protocol (only show if not the default tcp,udp).
	protos := f.effectiveProtos()
	if len(protos) == 1 {
		parts = append(parts, strings.ToLower(protos[0]))
	}

	// Source CIDR.
	if f.SrcCIDR != nil {
		parts = append(parts, "src:"+f.SrcCIDR.String())
	}

	// State (only show if not default).
	states := f.effectiveStates()
	if len(states) != 1 || states[0] != "established" {
		parts = append(parts, "state:"+strings.Join(states, ","))
	}

	// Direction (only show if not default "all").
	dirs := f.effectiveDirections()
	if len(dirs) == 1 {
		parts = append(parts, "dir:"+dirs[0])
	}

	// IP version (only show if not default "all").
	ipVers := f.effectiveIPVersions()
	if len(ipVers) == 1 {
		if ipVers[0] == "4" {
			parts = append(parts, "ipv4")
		} else {
			parts = append(parts, "ipv6")
		}
	}

	return strings.Join(parts, "  ")
}

func (f Filter) effectiveProtos() []string {
	if len(f.Protos) == 0 {
		return []string{"TCP", "UDP"}
	}
	return f.Protos
}

func (f Filter) effectiveStates() []string {
	if len(f.States) == 0 {
		return []string{"established"}
	}
	return f.States
}

func (f Filter) effectiveDirections() []string {
	if len(f.Directions) == 0 {
		return []string{"in", "out"}
	}
	return f.Directions
}

func (f Filter) effectiveIPVersions() []string {
	if len(f.IPVersions) == 0 {
		return []string{"4", "6"}
	}
	return f.IPVersions
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

// ParseCTOutput parses cilium bpf ct list output and returns unique peers
// matching the filter for the given podIP.
func ParseCTOutput(output string, podIP string, filter Filter) []Peer {
	protos := filter.effectiveProtos()
	directions := filter.effectiveDirections()
	ipVersions := filter.effectiveIPVersions()

	// Build IP version set.
	wantV4, wantV6 := false, false
	for _, v := range ipVersions {
		switch v {
		case "4":
			wantV4 = true
		case "6":
			wantV6 = true
		}
	}

	// Build direction set.
	dirIn := false
	dirOut := false
	for _, d := range directions {
		switch d {
		case "in":
			dirIn = true
		case "out":
			dirOut = true
		}
	}

	// Build prefixes: proto x direction.
	type dirPrefix struct {
		prefix string
		isOut  bool
	}
	var prefixes []dirPrefix
	for _, p := range protos {
		if dirIn {
			prefixes = append(prefixes, dirPrefix{p + " IN ", false})
		}
		if dirOut {
			prefixes = append(prefixes, dirPrefix{p + " OUT ", true})
		}
	}

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

	// Build pod IP prefix patterns for both v4 and v6 formats.
	podIPv4Prefix := podIP + ":"
	podIPv6Prefix := "[" + podIP + "]:"

	seen := make(map[string]bool)
	var peers []Peer

	for line := range strings.SplitSeq(output, "\n") {
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
			continue
		}

		// 2. Extract fields.
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}

		// For IN:  fields[2] = remote (peer), fields[4] = pod (dst)
		// For OUT: fields[2] = pod (src),     fields[4] = remote (peer)
		var podAddr, peerAddr string
		if isOutDir {
			podAddr = fields[2]
			peerAddr = fields[4]
		} else {
			podAddr = fields[4]
			peerAddr = fields[2]
		}

		// 3. Pod IP match — supports both "ip:port" and "[ip]:port".
		if !strings.HasPrefix(podAddr, podIPv4Prefix) && !strings.HasPrefix(podAddr, podIPv6Prefix) {
			continue
		}

		// 4. IP version filter.
		isV6 := strings.HasPrefix(peerAddr, "[")
		if isV6 && !wantV6 {
			continue
		}
		if !isV6 && !wantV4 {
			continue
		}

		// 5. State detection (always needed for Peer.State).
		isClosing := strings.Contains(line, "RxClosing") || strings.Contains(line, "TxClosing")

		// 6. State filter.
		if !stateAll {
			if stateEstablished && !stateClosing && isClosing {
				continue
			}
			if stateClosing && !stateEstablished && !isClosing {
				continue
			}
		}

		// 7. Port — DstPort is always extracted from fields[4].
		// For IN:  fields[4] = podIP:podPort → pod's listening port.
		// For OUT: fields[4] = remoteIP:remotePort → remote destination port.
		_, dstPort := splitAddrPort(fields[4])
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

		// 8. Source CIDR — applies to the peer address.
		if filter.SrcCIDR != nil {
			srcHost, _ := splitAddrPort(peerAddr)
			srcIP := net.ParseIP(srcHost)
			if srcIP == nil || !filter.SrcCIDR.Contains(srcIP) {
				continue
			}
		}

		// 9. Dedup + collect (keyed on peer address + direction).
		dedupKey := peerAddr
		if dirIn && dirOut {
			// When showing both directions, same peer can appear as IN and OUT.
			direction := "in"
			if isOutDir {
				direction = "out"
			}
			dedupKey = direction + ":" + peerAddr
		}
		if seen[dedupKey] {
			continue
		}
		seen[dedupKey] = true

		proto := fields[0]
		state := "established"
		if isClosing {
			state = "closing"
		}
		direction := "in"
		if isOutDir {
			direction = "out"
		}
		ipVersion := "4"
		if isV6 {
			ipVersion = "6"
		}

		// Parse rich fields. Cilium versions use different naming:
		// - Newer: RxBytes, TxBytes, RxPackets, TxPackets
		// - Older camelCase: Bytes, Packets (combined)
		// - Some versions: rx_bytes, tx_bytes, rx_packets, tx_packets
		rxBytes := parseKVUint(line, "RxBytes")
		if rxBytes == 0 {
			rxBytes = parseKVUint(line, "rx_bytes")
		}
		txBytes := parseKVUint(line, "TxBytes")
		if txBytes == 0 {
			txBytes = parseKVUint(line, "tx_bytes")
		}
		rxPackets := parseKVUint(line, "RxPackets")
		if rxPackets == 0 {
			rxPackets = parseKVUint(line, "rx_packets")
		}
		txPackets := parseKVUint(line, "TxPackets")
		if txPackets == 0 {
			txPackets = parseKVUint(line, "tx_packets")
		}

		// Older Cilium uses "Packets" and "Bytes" (combined).
		totalBytes := parseKVUint(line, "Bytes")
		if totalBytes == 0 {
			totalBytes = parseKVUint(line, "bytes")
		}
		totalPackets := parseKVUint(line, "Packets")
		if totalPackets == 0 {
			totalPackets = parseKVUint(line, "packets")
		}

		// Prefer split fields; fall back to combined.
		if rxBytes == 0 && txBytes == 0 && totalBytes > 0 {
			rxBytes = totalBytes
		}
		if rxPackets == 0 && txPackets == 0 && totalPackets > 0 {
			rxPackets = totalPackets
		}

		peers = append(peers, Peer{
			Src:          peerAddr,
			DstPort:      dstPort,
			Proto:        proto,
			State:        state,
			Direction:    direction,
			IPVersion:    ipVersion,
			Bytes:        rxBytes + txBytes,
			Packets:      rxPackets + txPackets,
			RxBytes:      rxBytes,
			TxBytes:      txBytes,
			RxPackets:    rxPackets,
			TxPackets:    txPackets,
			Expires:      uint32(parseKVUint(line, "expires")),
			LastRxReport: uint32(parseKVUint(line, "LastRxReport")),
			LastTxReport: uint32(parseKVUint(line, "LastTxReport")),
			RxFlagsSeen:  parseKVHex(line, "RxFlagsSeen"),
			TxFlagsSeen:  parseKVHex(line, "TxFlagsSeen"),
		})
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
	// Try net.SplitHostPort first which handles [ipv6]:port.
	host, portStr, err := net.SplitHostPort(addr)
	if err == nil {
		port, err := strconv.Atoi(portStr)
		if err == nil {
			return host, port
		}
		return host, 0
	}
	// Fallback for bare addresses without port.
	return addr, 0
}

func compareIP(a, b string) int {
	aIP := net.ParseIP(a)
	bIP := net.ParseIP(b)
	if aIP == nil || bIP == nil {
		// Fall back to string comparison for unparseable IPs.
		if a < b {
			return -1
		}
		if a > b {
			return 1
		}
		return 0
	}
	aBytes := aIP.To16()
	bBytes := bIP.To16()
	for i := range aBytes {
		if aBytes[i] < bBytes[i] {
			return -1
		}
		if aBytes[i] > bBytes[i] {
			return 1
		}
	}
	return 0
}
