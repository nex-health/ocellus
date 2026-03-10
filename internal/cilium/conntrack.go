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

	if err := f.parsePort(opts.Port); err != nil {
		return f, err
	}
	if err := f.parseProtos(opts.Proto); err != nil {
		return f, err
	}
	if err := f.parseSrcCIDR(opts.Src); err != nil {
		return f, err
	}
	f.parseStates(opts.State)
	if err := f.parseDirection(opts.Direction); err != nil {
		return f, err
	}
	if err := f.parseIPVersion(opts.IPVersion); err != nil {
		return f, err
	}

	return f, nil
}

func (f *Filter) parsePort(port string) error {
	if port == "" {
		return nil
	}
	before, after, hasRange := strings.Cut(port, "-")
	if !hasRange {
		return f.parseSinglePort(port)
	}
	return f.parsePortRange(before, after, port)
}

func (f *Filter) parseSinglePort(port string) error {
	p, err := strconv.Atoi(port)
	if err != nil {
		return fmt.Errorf("invalid port: %s", port)
	}
	if p < 1 || p > 65535 {
		return fmt.Errorf("invalid port %d: must be 1-65535", p)
	}
	f.PortMin = p
	f.PortMax = p
	return nil
}

func (f *Filter) parsePortRange(loStr, hiStr, raw string) error {
	lo, err := strconv.Atoi(loStr)
	if err != nil {
		return fmt.Errorf("invalid port range: %s", raw)
	}
	hi, err := strconv.Atoi(hiStr)
	if err != nil {
		return fmt.Errorf("invalid port range: %s", raw)
	}
	if lo < 1 || lo > 65535 || hi < 1 || hi > 65535 {
		return fmt.Errorf("invalid port range %s: ports must be 1-65535", raw)
	}
	if lo > hi {
		return fmt.Errorf("invalid port range %d-%d: min must be <= max", lo, hi)
	}
	f.PortMin = lo
	f.PortMax = hi
	return nil
}

func (f *Filter) parseProtos(proto string) error {
	if proto == "" {
		proto = "tcp,udp"
	}
	for p := range strings.SplitSeq(proto, ",") {
		p = strings.ToUpper(strings.TrimSpace(p))
		if p != "" {
			f.Protos = append(f.Protos, p)
		}
	}
	for _, p := range f.Protos {
		if p != "TCP" && p != "UDP" {
			return fmt.Errorf("unsupported protocol %q (valid: tcp, udp)", strings.ToLower(p))
		}
	}
	return nil
}

func (f *Filter) parseSrcCIDR(src string) error {
	if src == "" {
		return nil
	}
	cidrStr := src
	if !strings.Contains(cidrStr, "/") {
		cidrStr += "/32"
	}
	_, cidr, err := net.ParseCIDR(cidrStr)
	if err != nil {
		return fmt.Errorf("invalid source CIDR: %s", src)
	}
	f.SrcCIDR = cidr
	return nil
}

func (f *Filter) parseStates(state string) {
	if state == "" {
		state = "established"
	}
	for s := range strings.SplitSeq(state, ",") {
		s = strings.ToLower(strings.TrimSpace(s))
		if s != "" {
			f.States = append(f.States, s)
		}
	}
}

func (f *Filter) parseDirection(dir string) error {
	dir = strings.ToLower(strings.TrimSpace(dir))
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
		return fmt.Errorf("invalid direction %q (valid: in, out, all)", dir)
	}
	return nil
}

func (f *Filter) parseIPVersion(ipv string) error {
	ipv = strings.TrimSpace(ipv)
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
		return fmt.Errorf("invalid IP version %q (valid: 4, 6, all)", ipv)
	}
	return nil
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
		return strings.Compare(a, b)
	}
	return strings.Compare(string(aIP.To16()), string(bIP.To16()))
}
