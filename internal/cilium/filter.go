package cilium

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

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

	protos := f.effectiveProtos()
	if len(protos) == 1 {
		parts = append(parts, strings.ToLower(protos[0]))
	}

	if f.SrcCIDR != nil {
		parts = append(parts, "src:"+f.SrcCIDR.String())
	}

	states := f.effectiveStates()
	if len(states) != 1 || states[0] != "established" {
		parts = append(parts, "state:"+strings.Join(states, ","))
	}

	dirs := f.effectiveDirections()
	if len(dirs) == 1 {
		parts = append(parts, "dir:"+dirs[0])
	}

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
