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

func (m Model) handlePodScroll(msg tea.KeyMsg) (Model, bool) {
	switch msg.String() {
	case "G":
		m.cursor = max(len(m.config.Pods)-1, 0)
		m.clampPodScroll()
	case "ctrl+d":
		m.cursor += m.podPaneHeight() / 2
		if m.cursor >= len(m.config.Pods) {
			m.cursor = len(m.config.Pods) - 1
		}
		if m.cursor < 0 {
			m.cursor = 0
		}
		m.clampPodScroll()
	case "ctrl+u":
		m.cursor -= m.podPaneHeight() / 2
		if m.cursor < 0 {
			m.cursor = 0
		}
		m.clampPodScroll()
	case "H":
		m.cursor = m.podScroll
	case "M":
		mid := m.podScroll + m.podPaneHeight()/2
		if mid >= len(m.config.Pods) {
			mid = len(m.config.Pods) - 1
		}
		if mid < 0 {
			mid = 0
		}
		m.cursor = mid
	case "L":
		bottom := m.podScroll + m.podPaneHeight() - 1
		if bottom >= len(m.config.Pods) {
			bottom = len(m.config.Pods) - 1
		}
		if bottom < 0 {
			bottom = 0
		}
		m.cursor = bottom
	case "j", "down":
		if m.cursor < len(m.config.Pods)-1 {
			m.cursor++
		}
		m.clampPodScroll()
	case "k", "up":
		if m.cursor > 0 {
			m.cursor--
		}
		m.clampPodScroll()
	default:
		return m, false
	}
	return m, true
}

func (m Model) updatePodList(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if m.pendingKey == "g" {
		m.pendingKey = ""
		if msg.String() == "g" {
			m.cursor = 0
			m.clampPodScroll()
			return m, nil
		}
	}

	if scrolled, ok := m.handlePodScroll(msg); ok {
		return scrolled, nil
	}

	switch msg.String() {
	case "g":
		m.pendingKey = "g"
		return m, pendingKeyTimeout()
	case "enter":
		m.mode = viewPeers
		m.scroll = 0
	case "tab":
		for offset := 1; offset < len(m.config.Pods); offset++ {
			idx := (m.cursor + offset) % len(m.config.Pods)
			if len(m.peers[m.config.Pods[idx].Name]) > 0 {
				m.cursor = idx
				break
			}
		}
		m.clampPodScroll()
	case "shift+tab":
		for offset := 1; offset < len(m.config.Pods); offset++ {
			idx := (m.cursor - offset + len(m.config.Pods)) % len(m.config.Pods)
			if len(m.peers[m.config.Pods[idx].Name]) > 0 {
				m.cursor = idx
				break
			}
		}
		m.clampPodScroll()
	}
	return m, nil
}

// handleSearchKey processes key input while in search mode.
func (m Model) handleSearchKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.searching = false
		m.searchQuery = ""
		m.scroll = 0
	case "enter":
		m.searching = false
	case "backspace":
		if len(m.searchQuery) > 0 {
			m.searchQuery = m.searchQuery[:len(m.searchQuery)-1]
			m.scroll = 0
		}
	default:
		if msg.Type == tea.KeyRunes {
			m.searchQuery += string(msg.Runes)
			m.scroll = 0
		}
	}
	return m, nil
}

// handlePeerScroll processes scroll/navigation keys in the peer list.
// It returns the updated model and true if a scroll key was handled.
func (m Model) handlePeerScroll(msg tea.KeyMsg) (Model, bool) {
	switch msg.String() {
	case "G":
		m.scroll = m.maxScroll()
	case "ctrl+d":
		m.scroll += m.peerPaneHeight() / 2
		m.clampScroll()
	case "ctrl+u":
		m.scroll -= m.peerPaneHeight() / 2
		if m.scroll < 0 {
			m.scroll = 0
		}
	case "H":
		// top of visible — no-op for scroll
	case "M":
		m.scroll += m.peerPaneHeight() / 2
		m.clampScroll()
	case "L":
		m.scroll += m.peerPaneHeight() - 1
		m.clampScroll()
	case "j", "down":
		m.scroll++
		m.clampScroll()
	case "k", "up":
		if m.scroll > 0 {
			m.scroll--
		}
	case "pgdown":
		m.scroll += m.peerPaneHeight()
		m.clampScroll()
	case "pgup":
		m.scroll -= m.peerPaneHeight()
		if m.scroll < 0 {
			m.scroll = 0
		}
	case "home":
		m.scroll = 0
	case "end":
		m.scroll = m.maxScroll()
	default:
		return m, false
	}
	m.paused = true
	return m, true
}

func (m Model) updatePeerList(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if m.searching {
		return m.handleSearchKey(msg)
	}

	if m.pendingKey == "g" {
		m.pendingKey = ""
		if msg.String() == "g" {
			m.paused = true
			m.scroll = 0
			return m, nil
		}
	}

	if scrolled, ok := m.handlePeerScroll(msg); ok {
		return scrolled, nil
	}

	switch msg.String() {
	case "g":
		m.pendingKey = "g"
		return m, pendingKeyTimeout()
	case "esc":
		m.mode = viewPods
		m.scroll = 0
		m.searchQuery = ""
		m.stateFilter = stateAll
		m.protoFilter = protoAll
		m.dirFilter = dirAll
		m.ipVerFilter = ipVerAll
	case "f":
		m.stateFilter = (m.stateFilter + 1) % stateFilterCount
		m.scroll = 0
	case "F":
		m.protoFilter = (m.protoFilter + 1) % protoFilterCount
		m.scroll = 0
	case "D":
		m.dirFilter = (m.dirFilter + 1) % dirFilterCount
		m.scroll = 0
	case "V":
		m.ipVerFilter = (m.ipVerFilter + 1) % ipVerFilterCount
		m.scroll = 0
	case "s":
		m.sortField = (m.sortField + 1) % sortFieldCount
		m.scroll = 0
	case "S":
		m.sortReverse = !m.sortReverse
		m.scroll = 0
	case "/":
		m.searching = true
		m.searchQuery = ""
		m.scroll = 0
	case "n":
		if m.searchQuery != "" {
			m.paused = true
			m.scroll++
			if peers := m.selectedPeers(); len(peers) > 0 && m.scroll > len(peers)-1 {
				m.scroll = len(peers) - 1
			}
		}
	case "N":
		if m.searchQuery != "" {
			m.paused = true
			if m.scroll > 0 {
				m.scroll--
			}
		}
	}
	return m, nil
}
