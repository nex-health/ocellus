package tui

import (
	"fmt"
	"maps"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/nex-health/ocellus/internal/capture"
)

// handlePollResult processes a poll result message.
func (m Model) handlePollResult(msg pollResultMsg) (Model, tea.Cmd) {
	m.polling = false
	m.lastErrors = msg.errors
	maps.Copy(m.peers, msg.peers)
	for name := range msg.exited {
		m.exited[name] = true
	}
	// Refresh the pod list so new pods appear (scaling, rollouts, restarts).
	if msg.pods != nil {
		m.config.Pods = msg.pods
	}

	m.updateBytesRate(msg.timestamp)
	m.timestamp = msg.timestamp

	if m.recorder != nil {
		snap := capture.Snapshot{
			Timestamp: msg.timestamp,
			Pods:      m.peers,
			Exited:    m.exited,
			Errors:    m.lastErrors,
		}
		if err := m.recorder.OnPoll(snap); err != nil {
			m.dumpStatus = fmt.Sprintf("record error: %v", err)
			m.dumpStatusT = time.Now()
		}
	}

	m.clampCursor()
	m.clampPodScroll()
	m.clampScroll()

	if m.paused {
		return m, nil
	}
	return m, tickAfter(m.config.Interval)
}

// updateBytesRate computes the bytes/sec rate from the previous poll.
func (m *Model) updateBytesRate(ts time.Time) {
	var currentTotalBytes uint64
	for _, p := range m.config.Pods {
		for _, peer := range m.peers[p.Name] {
			currentTotalBytes += peer.Bytes
		}
	}

	if m.prevTotalBytes > 0 && !m.timestamp.IsZero() {
		elapsed := ts.Sub(m.timestamp).Seconds()
		if elapsed > 0 && currentTotalBytes > m.prevTotalBytes {
			m.bytesPerSec = uint64(float64(currentTotalBytes-m.prevTotalBytes) / elapsed)
		} else {
			m.bytesPerSec = 0
		}
	}
	m.prevTotalBytes = currentTotalBytes
}

// clampCursor ensures the pod cursor is within bounds.
func (m *Model) clampCursor() {
	if len(m.config.Pods) == 0 {
		m.cursor = 0
	} else if m.cursor >= len(m.config.Pods) {
		m.cursor = len(m.config.Pods) - 1
	}
}

func (m Model) updatePodList(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	// Handle pending key chord.
	if m.pendingKey == "g" {
		m.pendingKey = ""
		if msg.String() == "g" {
			m.cursor = 0
			m.clampPodScroll()
			return m, nil
		}
		// Not 'g' — fall through to normal handling.
	}

	switch msg.String() {
	case "g":
		m.pendingKey = "g"
		return m, pendingKeyTimeout()
	case "G":
		m.cursor = max(len(m.config.Pods)-1, 0)
		m.clampPodScroll()
		return m, nil
	case "ctrl+d":
		half := m.podPaneHeight() / 2
		m.cursor += half
		if m.cursor >= len(m.config.Pods) {
			m.cursor = len(m.config.Pods) - 1
		}
		if m.cursor < 0 {
			m.cursor = 0
		}
		m.clampPodScroll()
		return m, nil
	case "ctrl+u":
		half := m.podPaneHeight() / 2
		m.cursor -= half
		if m.cursor < 0 {
			m.cursor = 0
		}
		m.clampPodScroll()
		return m, nil
	case "H":
		m.cursor = m.podScroll
		return m, nil
	case "M":
		mid := m.podScroll + m.podPaneHeight()/2
		if mid >= len(m.config.Pods) {
			mid = len(m.config.Pods) - 1
		}
		if mid < 0 {
			mid = 0
		}
		m.cursor = mid
		return m, nil
	case "L":
		bottom := m.podScroll + m.podPaneHeight() - 1
		if bottom >= len(m.config.Pods) {
			bottom = len(m.config.Pods) - 1
		}
		if bottom < 0 {
			bottom = 0
		}
		m.cursor = bottom
		return m, nil
	case "j", "down":
		if m.cursor < len(m.config.Pods)-1 {
			m.cursor++
		}
		m.clampPodScroll()
		return m, nil
	case "k", "up":
		if m.cursor > 0 {
			m.cursor--
		}
		m.clampPodScroll()
		return m, nil
	case "enter":
		m.mode = viewPeers
		m.scroll = 0
		return m, nil
	case "tab":
		for offset := 1; offset < len(m.config.Pods); offset++ {
			idx := (m.cursor + offset) % len(m.config.Pods)
			if len(m.peers[m.config.Pods[idx].Name]) > 0 {
				m.cursor = idx
				break
			}
		}
		m.clampPodScroll()
		return m, nil
	case "shift+tab":
		for offset := 1; offset < len(m.config.Pods); offset++ {
			idx := (m.cursor - offset + len(m.config.Pods)) % len(m.config.Pods)
			if len(m.peers[m.config.Pods[idx].Name]) > 0 {
				m.cursor = idx
				break
			}
		}
		m.clampPodScroll()
		return m, nil
	}
	return m, nil
}

func (m Model) updatePeerList(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	// Search mode intercepts most keys.
	if m.searching {
		switch msg.String() {
		case "esc":
			m.searching = false
			m.searchQuery = ""
			m.scroll = 0
			return m, nil
		case "enter":
			m.searching = false
			return m, nil
		case "backspace":
			if len(m.searchQuery) > 0 {
				m.searchQuery = m.searchQuery[:len(m.searchQuery)-1]
				m.scroll = 0
			}
			return m, nil
		default:
			if msg.Type == tea.KeyRunes {
				m.searchQuery += string(msg.Runes)
				m.scroll = 0
			}
			return m, nil
		}
	}

	// Handle pending key chord (only when not searching).
	if m.pendingKey == "g" {
		m.pendingKey = ""
		if msg.String() == "g" {
			m.paused = true
			m.scroll = 0
			return m, nil
		}
		// Not 'g' — fall through to normal handling.
	}

	switch msg.String() {
	case "g":
		m.pendingKey = "g"
		return m, pendingKeyTimeout()
	case "G":
		m.paused = true
		m.scroll = m.maxScroll()
		return m, nil
	case "ctrl+d":
		m.paused = true
		half := m.peerPaneHeight() / 2
		m.scroll += half
		m.clampScroll()
		return m, nil
	case "ctrl+u":
		m.paused = true
		half := m.peerPaneHeight() / 2
		m.scroll -= half
		if m.scroll < 0 {
			m.scroll = 0
		}
		return m, nil
	case "H":
		m.paused = true
		// Already at top of visible — no-op for scroll.
		return m, nil
	case "M":
		m.paused = true
		m.scroll += m.peerPaneHeight() / 2
		m.clampScroll()
		return m, nil
	case "L":
		m.paused = true
		m.scroll += m.peerPaneHeight() - 1
		m.clampScroll()
		return m, nil
	case "j", "down":
		m.paused = true
		m.scroll++
		m.clampScroll()
		return m, nil
	case "k", "up":
		m.paused = true
		if m.scroll > 0 {
			m.scroll--
		}
		return m, nil
	case "pgdown":
		m.paused = true
		m.scroll += m.peerPaneHeight()
		m.clampScroll()
		return m, nil
	case "pgup":
		m.paused = true
		m.scroll -= m.peerPaneHeight()
		if m.scroll < 0 {
			m.scroll = 0
		}
		return m, nil
	case "home":
		m.paused = true
		m.scroll = 0
		return m, nil
	case "end":
		m.paused = true
		m.scroll = m.maxScroll()
		return m, nil
	case "esc":
		m.mode = viewPods
		m.scroll = 0
		m.searchQuery = ""
		m.stateFilter = stateAll
		m.protoFilter = protoAll
		m.dirFilter = dirAll
		m.ipVerFilter = ipVerAll
		return m, nil
	case "f":
		m.stateFilter = (m.stateFilter + 1) % stateFilterCount
		m.scroll = 0
		return m, nil
	case "F":
		m.protoFilter = (m.protoFilter + 1) % protoFilterCount
		m.scroll = 0
		return m, nil
	case "D":
		m.dirFilter = (m.dirFilter + 1) % dirFilterCount
		m.scroll = 0
		return m, nil
	case "V":
		m.ipVerFilter = (m.ipVerFilter + 1) % ipVerFilterCount
		m.scroll = 0
		return m, nil
	case "s":
		m.sortField = (m.sortField + 1) % sortFieldCount
		m.scroll = 0
		return m, nil
	case "S":
		m.sortReverse = !m.sortReverse
		m.scroll = 0
		return m, nil
	case "/":
		m.searching = true
		m.searchQuery = ""
		m.scroll = 0
		return m, nil
	case "n":
		// Next: scroll forward by 1 if search is active.
		if m.searchQuery != "" {
			m.paused = true
			m.scroll++
			peers := m.selectedPeers()
			if last := len(peers) - 1; last >= 0 && m.scroll > last {
				m.scroll = last
			}
		}
		return m, nil
	case "N":
		// Previous: scroll backward by 1 if search is active.
		if m.searchQuery != "" {
			m.paused = true
			if m.scroll > 0 {
				m.scroll--
			}
		}
		return m, nil
	}
	return m, nil
}
