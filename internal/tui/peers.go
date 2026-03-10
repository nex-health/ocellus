package tui

import (
	"sort"
	"strings"

	"github.com/nex-health/ocellus/internal/cilium"
)

// highlightMatch returns text with the first case-insensitive occurrence of query
// wrapped in searchMatchStyle. Returns text unchanged if query is empty or not found.
func highlightMatch(text, query string) string {
	if query == "" {
		return text
	}
	lower := strings.ToLower(text)
	q := strings.ToLower(query)
	idx := strings.Index(lower, q)
	if idx < 0 {
		return text
	}
	before := text[:idx]
	match := text[idx : idx+len(query)]
	after := text[idx+len(query):]
	return before + searchMatchStyle.Render(match) + after
}

// filteredPeers returns peers matching the current search query and quick filters.
func (m Model) filteredPeers(peers []cilium.Peer) []cilium.Peer {
	noFiltersActive := m.searchQuery == "" &&
		m.stateFilter == stateAll &&
		m.protoFilter == protoAll &&
		m.dirFilter == dirAll &&
		m.ipVerFilter == ipVerAll
	if noFiltersActive {
		return peers
	}
	q := strings.ToLower(m.searchQuery)
	var filtered []cilium.Peer
	for _, p := range peers {
		if m.stateFilter != stateAll && !strings.EqualFold(p.State, m.stateFilter.String()) {
			continue
		}
		if m.protoFilter != protoAll && !strings.EqualFold(p.Proto, m.protoFilter.String()) {
			continue
		}
		if m.dirFilter != dirAll && !strings.EqualFold(p.Direction, m.dirFilter.String()) {
			continue
		}
		if m.ipVerFilter != ipVerAll {
			wantV6 := m.ipVerFilter == ipVer6
			isV6 := strings.Contains(p.Src, "[")
			if wantV6 != isV6 {
				continue
			}
		}
		if q != "" && !strings.Contains(strings.ToLower(p.Src), q) {
			continue
		}
		filtered = append(filtered, p)
	}
	return filtered
}

// sortPeers returns a sorted copy of peers.
func sortPeers(peers []cilium.Peer, field sortField, reverse bool) []cilium.Peer {
	sorted := make([]cilium.Peer, len(peers))
	copy(sorted, peers)
	sort.SliceStable(sorted, func(i, j int) bool {
		var less bool
		switch field {
		case sortPort:
			less = sorted[i].DstPort < sorted[j].DstPort
		case sortProto:
			less = sorted[i].Proto < sorted[j].Proto
		case sortDir:
			less = sorted[i].Direction < sorted[j].Direction
		case sortState:
			less = sorted[i].State < sorted[j].State
		case sortBytes:
			less = sorted[i].Bytes < sorted[j].Bytes
		default: // sortSrc
			less = cilium.ComparePeerAddr(sorted[i].Src, sorted[j].Src) < 0
		}
		if reverse {
			return !less
		}
		return less
	})
	return sorted
}

// selectedPeers returns the filtered+sorted peers for the currently selected pod.
func (m Model) selectedPeers() []cilium.Peer {
	if len(m.config.Pods) == 0 || m.cursor >= len(m.config.Pods) {
		return nil
	}
	raw := m.peers[m.config.Pods[m.cursor].Name]
	filtered := m.filteredPeers(raw)
	return sortPeers(filtered, m.sortField, m.sortReverse)
}
