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
	Src     string // e.g. "10.4.166.193:52628"
	DstPort int    // destination port on the pod
	Proto   string // "TCP" or "UDP"
	State   string // "established" or "closing"
}

// Filter controls which conntrack entries are included.
type Filter struct {
	PortMin int        // 0 = no lower bound
	PortMax int        // 0 = no upper bound; both 0 = all ports
	Protos  []string   // e.g. ["TCP", "UDP"]; empty = ["TCP"]
	SrcCIDR *net.IPNet // nil = no source filter
	States  []string   // "established", "closing", "all"; empty = ["established"]
}

// FilterOpts holds raw string options for building a Filter.
type FilterOpts struct {
	Port  string // e.g. "5432", "5432-5440", or ""
	Proto string // e.g. "tcp", "udp", "tcp,udp"
	Src   string // e.g. "10.4.166.0/24", "10.0.0.1", or ""
	State string // e.g. "established", "closing", "all"
}

// NewFilter creates a Filter from string options, returning an error if any
// option is invalid.
func NewFilter(opts FilterOpts) (Filter, error) {
	var f Filter

	// Parse port.
	if opts.Port != "" {
		if idx := strings.Index(opts.Port, "-"); idx >= 0 {
			min, err := strconv.Atoi(opts.Port[:idx])
			if err != nil {
				return f, fmt.Errorf("invalid port range: %s", opts.Port)
			}
			max, err := strconv.Atoi(opts.Port[idx+1:])
			if err != nil {
				return f, fmt.Errorf("invalid port range: %s", opts.Port)
			}
			if min < 1 || min > 65535 || max < 1 || max > 65535 {
				return f, fmt.Errorf("invalid port range %s: ports must be 1-65535", opts.Port)
			}
			if min > max {
				return f, fmt.Errorf("invalid port range %d-%d: min must be <= max", min, max)
			}
			f.PortMin = min
			f.PortMax = max
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
		proto = "tcp"
	}
	for _, p := range strings.Split(proto, ",") {
		p = strings.ToUpper(strings.TrimSpace(p))
		if p != "" {
			f.Protos = append(f.Protos, p)
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
	for _, s := range strings.Split(state, ",") {
		s = strings.ToLower(strings.TrimSpace(s))
		if s != "" {
			f.States = append(f.States, s)
		}
	}

	return f, nil
}

// FilterSummary returns a human-readable summary of the filter for display.
func (f Filter) FilterSummary() string {
	var parts []string

	// Port.
	if f.PortMin > 0 && f.PortMin == f.PortMax {
		parts = append(parts, fmt.Sprintf(":%d", f.PortMin))
	} else if f.PortMin > 0 || f.PortMax > 0 {
		min := f.PortMin
		if min == 0 {
			min = 1
		}
		max := f.PortMax
		if max == 0 {
			max = 65535
		}
		parts = append(parts, fmt.Sprintf(":%d-%d", min, max))
	} else {
		parts = append(parts, "all ports")
	}

	// Protocol (only show if not just tcp).
	protos := f.effectiveProtos()
	if len(protos) != 1 || protos[0] != "TCP" {
		parts = append(parts, strings.ToLower(strings.Join(protos, "+")))
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

	return strings.Join(parts, "  ")
}

func (f Filter) effectiveProtos() []string {
	if len(f.Protos) == 0 {
		return []string{"TCP"}
	}
	return f.Protos
}

func (f Filter) effectiveStates() []string {
	if len(f.States) == 0 {
		return []string{"established"}
	}
	return f.States
}

// ParseCTOutput parses cilium bpf ct list output and returns unique peers
// with active IN connections to the given podIP matching the filter.
func ParseCTOutput(output string, podIP string, filter Filter) []Peer {
	protos := filter.effectiveProtos()
	prefixes := make([]string, len(protos))
	for i, p := range protos {
		prefixes[i] = p + " IN "
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

	dstPrefix := fmt.Sprintf("-> %s:", podIP)

	seen := make(map[string]bool)
	var peers []Peer

	for _, line := range strings.Split(output, "\n") {
		// 1. Protocol + direction prefix.
		matchedProto := false
		for _, pfx := range prefixes {
			if strings.HasPrefix(line, pfx) {
				matchedProto = true
				break
			}
		}
		if !matchedProto {
			continue
		}

		// 2. Destination IP match.
		if !strings.Contains(line, dstPrefix) {
			continue
		}

		// 3. State detection (always needed for Peer.State).
		isClosing := strings.Contains(line, "RxClosing") || strings.Contains(line, "TxClosing")

		// 4. State filter.
		if !stateAll {
			if stateEstablished && !stateClosing && isClosing {
				continue
			}
			if stateClosing && !stateEstablished && !isClosing {
				continue
			}
		}

		// 5. Extract fields.
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		src := fields[2]
		dst := fields[4]

		// 6. Port range.
		dstPort := 0
		if idx := strings.LastIndex(dst, ":"); idx >= 0 {
			if p, err := strconv.Atoi(dst[idx+1:]); err == nil {
				dstPort = p
			}
		}
		if filter.PortMin > 0 || filter.PortMax > 0 {
			min := filter.PortMin
			max := filter.PortMax
			if min == 0 {
				min = 1
			}
			if max == 0 {
				max = 65535
			}
			if dstPort < min || dstPort > max {
				continue
			}
		}

		// 7. Source CIDR.
		if filter.SrcCIDR != nil {
			srcHost := src
			if idx := strings.LastIndex(srcHost, ":"); idx >= 0 {
				srcHost = srcHost[:idx]
			}
			srcIP := net.ParseIP(srcHost)
			if srcIP == nil || !filter.SrcCIDR.Contains(srcIP) {
				continue
			}
		}

		// 8. Dedup + collect.
		if seen[src] {
			continue
		}
		seen[src] = true

		proto := fields[0]
		state := "established"
		if isClosing {
			state = "closing"
		}

		peers = append(peers, Peer{
			Src:     src,
			DstPort: dstPort,
			Proto:   proto,
			State:   state,
		})
	}

	sort.Slice(peers, func(i, j int) bool {
		return ComparePeerAddr(peers[i].Src, peers[j].Src) < 0
	})
	return peers
}

// ComparePeerAddr compares two "ip:port" address strings numerically.
// Returns -1, 0, or 1 like strings.Compare but using numeric IP/port ordering.
func ComparePeerAddr(a, b string) int {
	aIP, aPort := splitHostPort(a)
	bIP, bPort := splitHostPort(b)

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

func splitHostPort(addr string) (string, int) {
	idx := strings.LastIndex(addr, ":")
	if idx < 0 {
		return addr, 0
	}
	port, err := strconv.Atoi(addr[idx+1:])
	if err != nil {
		return addr, 0
	}
	return addr[:idx], port
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
