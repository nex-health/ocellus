package cilium

// filterFlags holds pre-computed boolean flags derived from a Filter,
// used by both text and JSON conntrack parsers.
type filterFlags struct {
	wantV4           bool
	wantV6           bool
	dirIn            bool
	dirOut           bool
	stateAll         bool
	stateClosing     bool
	stateEstablished bool
}

// newFilterFlags pre-computes boolean flags from a Filter for efficient
// per-entry checking during conntrack parsing.
func newFilterFlags(f Filter) filterFlags {
	var ff filterFlags

	for _, v := range f.effectiveIPVersions() {
		switch v {
		case "4":
			ff.wantV4 = true
		case "6":
			ff.wantV6 = true
		}
	}

	for _, d := range f.effectiveDirections() {
		switch d {
		case "in":
			ff.dirIn = true
		case "out":
			ff.dirOut = true
		}
	}

	for _, s := range f.effectiveStates() {
		switch s {
		case "all":
			ff.stateAll = true
		case "closing":
			ff.stateClosing = true
		case "established":
			ff.stateEstablished = true
		}
	}

	return ff
}

// matchPort returns true if the given port passes the filter's port range.
func (f Filter) matchPort(port int) bool {
	if f.PortMin == 0 && f.PortMax == 0 {
		return true
	}
	lo := f.PortMin
	hi := f.PortMax
	if lo == 0 {
		lo = 1
	}
	if hi == 0 {
		hi = 65535
	}
	return port >= lo && port <= hi
}

// dedupPeer returns a dedup key for the peer, or "" if already seen.
func dedupPeer(peer *Peer, ff filterFlags, seen map[string]bool) string {
	if peer == nil {
		return ""
	}
	dedupKey := peer.Src
	if ff.dirIn && ff.dirOut {
		dedupKey = peer.Direction + ":" + peer.Src
	}
	if seen[dedupKey] {
		return ""
	}
	return dedupKey
}

// matchState returns true if the given closing status passes the state filter.
func (ff filterFlags) matchState(isClosing bool) bool {
	if ff.stateAll {
		return true
	}
	if ff.stateEstablished && !ff.stateClosing && isClosing {
		return false
	}
	if ff.stateClosing && !ff.stateEstablished && !isClosing {
		return false
	}
	return true
}
