package tui

import (
	"fmt"
	"sort"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/aurelcanciu/ocellus/internal/cilium"
	"github.com/aurelcanciu/ocellus/internal/format"
	"github.com/aurelcanciu/ocellus/internal/k8s"
)

type viewMode int

const (
	viewPods  viewMode = iota // pod list
	viewPeers                 // peer detail for selected pod
)

type sortField int

const (
	sortSrc sortField = iota
	sortPort
	sortProto
	sortState
	sortBytes
	sortFieldCount // sentinel for cycling
)

// Messages
type tickMsg struct{}

type pollResultMsg struct {
	peers     map[string][]cilium.Peer
	exited    map[string]bool
	timestamp time.Time
	errors    []string
}

type pendingKeyTimeoutMsg struct{}

// Config holds the parameters for the TUI.
type Config struct {
	Filter      cilium.Filter
	Namespace   string
	Target      k8s.Target
	Interval    time.Duration
	PollTimeout time.Duration // 0 = no timeout
	Client      ClusterClient
	Pods        []k8s.PodInfo
}

// Model is the Bubble Tea model for the ocellus TUI.
type Model struct {
	config      Config
	width       int
	height      int
	mode        viewMode
	cursor      int // selected pod index
	podScroll   int // scroll offset in pod list
	scroll      int // scroll offset in peer view
	peers       map[string][]cilium.Peer
	exited      map[string]bool
	timestamp   time.Time
	polling     bool
	paused      bool // polling paused due to user navigation
	quitting    bool
	sortField   sortField
	sortReverse bool
	searching   bool
	searchQuery string
	showHelp   bool
	lastErrors []string
	pendingKey string // for multi-key chords like "gg"
}

// New creates a new Model from the given config.
func New(cfg Config) Model {
	return Model{
		config:  cfg,
		peers:   make(map[string][]cilium.Peer),
		exited:  make(map[string]bool),
		polling: true,
	}
}

// errorSummary returns a short deduplicated summary of polling errors.
func errorSummary(errors []string) string {
	if len(errors) == 0 {
		return ""
	}
	// Strip "node <name>: " prefix to find distinct error reasons.
	reasons := make(map[string]int)
	for _, e := range errors {
		reason := e
		if idx := strings.Index(e, ": "); idx >= 0 {
			reason = e[idx+2:]
		}
		reasons[reason]++
	}
	var parts []string
	for reason, count := range reasons {
		if count > 1 {
			parts = append(parts, fmt.Sprintf("%s (x%d)", reason, count))
		} else {
			parts = append(parts, reason)
		}
	}
	sort.Strings(parts)
	return strings.Join(parts, "; ")
}

// startPoll creates a poll command with current model state.
func (m Model) startPoll() tea.Cmd {
	// Copy exited to avoid sharing mutable state with the poll goroutine.
	exitedCopy := make(map[string]bool, len(m.exited))
	for k, v := range m.exited {
		exitedCopy[k] = v
	}
	return pollCmd(m.config.Client, m.config.Namespace, m.config.Target, m.config.Filter, m.pollTargets(), exitedCopy, m.config.PollTimeout)
}

// pollTargets returns the pods to poll based on the current view mode.
func (m Model) pollTargets() []k8s.PodInfo {
	if m.mode == viewPeers && m.cursor < len(m.config.Pods) {
		return []k8s.PodInfo{m.config.Pods[m.cursor]}
	}
	return m.config.Pods
}

func (m Model) Init() tea.Cmd {
	return m.startPoll()
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.clampPodScroll()
		m.clampScroll()
		return m, nil

	case tickMsg:
		if m.quitting || m.paused {
			return m, nil
		}
		m.polling = true
		return m, m.startPoll()

	case pollResultMsg:
		m.polling = false
		m.timestamp = msg.timestamp
		m.lastErrors = msg.errors
		for name, p := range msg.peers {
			m.peers[name] = p
		}
		for name := range msg.exited {
			m.exited[name] = true
		}
		if len(m.config.Pods) == 0 {
			m.cursor = 0
		} else if m.cursor >= len(m.config.Pods) {
			m.cursor = len(m.config.Pods) - 1
		}
		m.clampPodScroll()
		m.clampScroll()
		if m.paused {
			return m, nil
		}
		return m, tickAfter(m.config.Interval)

	case pendingKeyTimeoutMsg:
		m.pendingKey = ""
		return m, nil

	case tea.KeyMsg:
		// Global keybindings.
		switch msg.String() {
		case "q", "ctrl+c":
			m.quitting = true
			return m, tea.Quit
		case "?":
			m.showHelp = !m.showHelp
			return m, nil
		case "r":
			m.paused = false
			m.polling = true
			return m, m.startPoll()
		case "p", " ":
			m.paused = !m.paused
			if !m.paused {
				m.polling = true
				return m, m.startPoll()
			}
			return m, nil
		}

		switch m.mode {
		case viewPods:
			return m.updatePodList(msg)
		case viewPeers:
			return m.updatePeerList(msg)
		}
	}
	return m, nil
}

// podPaneHeight returns lines available for pod rows in the pod list view.
// Layout: header(1) + divider(1) + [pod rows] + status(1)
func (m Model) podPaneHeight() int {
	h := m.height - 4 // header + divider + bottom divider + status
	if h < 1 {
		h = 1
	}
	return h
}

// clampPodScroll ensures podScroll keeps the cursor visible.
func (m *Model) clampPodScroll() {
	paneH := m.podPaneHeight()
	// Cursor above visible area.
	if m.cursor < m.podScroll {
		m.podScroll = m.cursor
	}
	// Cursor below visible area.
	if m.cursor >= m.podScroll+paneH {
		m.podScroll = m.cursor - paneH + 1
	}
	// Don't scroll past the end.
	maxScroll := len(m.config.Pods) - paneH
	if maxScroll < 0 {
		maxScroll = 0
	}
	if m.podScroll > maxScroll {
		m.podScroll = maxScroll
	}
	if m.podScroll < 0 {
		m.podScroll = 0
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
		m.cursor = len(m.config.Pods) - 1
		if m.cursor < 0 {
			m.cursor = 0
		}
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

// filteredPeers returns peers matching the current search query.
func (m Model) filteredPeers(peers []cilium.Peer) []cilium.Peer {
	if m.searchQuery == "" {
		return peers
	}
	q := strings.ToLower(m.searchQuery)
	var filtered []cilium.Peer
	for _, p := range peers {
		if strings.Contains(strings.ToLower(p.Src), q) {
			filtered = append(filtered, p)
		}
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

// peerPaneHeight returns lines available for peer data rows in the peer view.
// Layout: header(1) + divider(1) + subheader(1) + column header(1) + [peer rows] + status(1)
func (m Model) peerPaneHeight() int {
	fixed := 1 + 1 + 1 + 1 + 1 + 1 // header + divider + subheader + col header + bottom divider + status
	h := m.height - fixed
	if h < 1 {
		h = 1
	}
	return h
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

// maxScroll returns the maximum valid scroll value for the peer view.
func (m Model) maxScroll() int {
	peers := m.selectedPeers()
	limit := len(peers) - m.peerPaneHeight()
	if limit < 0 {
		limit = 0
	}
	return limit
}

// clampScroll ensures scroll is within bounds.
func (m *Model) clampScroll() {
	if m.mode != viewPeers {
		return
	}
	scrollMax := m.maxScroll()
	if m.scroll > scrollMax {
		m.scroll = scrollMax
	}
	if m.scroll < 0 {
		m.scroll = 0
	}
}

func (m Model) View() string {
	if m.quitting {
		return ""
	}

	w := m.width
	if w == 0 {
		w = 80
	}

	if m.showHelp {
		return m.viewHelp(w)
	}

	switch m.mode {
	case viewPeers:
		return m.viewPeerList(w)
	default:
		return m.viewPodList(w)
	}
}

func (m Model) viewHelp(w int) string {
	var b strings.Builder

	m.renderHeader(&b, w)

	help := []string{
		"Keybindings",
		"",
		"  q / Ctrl+C    Quit",
		"  j/k / Up/Down Navigate",
		"  enter         Select pod",
		"  esc           Back / Clear search",
		"  p / space     Toggle pause",
		"  r             Resume polling",
		"  s             Cycle sort field",
		"  S             Toggle reverse sort",
		"  /             Search peers",
		"  n/N           Next/prev search match",
		"  tab/shift+tab Jump to next/prev pod with peers",
		"  ?             Toggle this help",
		"  gg            Jump to top",
		"  G             Jump to bottom",
		"  H/M/L         Top/middle/bottom of screen",
		"  Ctrl+d/u      Half-page down/up",
		"  pgup/pgdn     Page scroll",
		"  home/end      Jump to top/bottom",
	}

	for _, line := range help {
		b.WriteString("  " + line + "\n")
	}

	// Fill remaining space.
	usedLines := 2 + len(help) + 1 + 1
	for i := usedLines; i < m.height; i++ {
		b.WriteString("\n")
	}

	b.WriteString(dividerStyle.Render(strings.Repeat("─", w)))
	b.WriteString("\n")

	keys := fmt.Sprintf("  %s close help", statusBarKeyStyle.Render("?"))
	padLen := w - lipgloss.Width(keys) - 2
	if padLen < 0 {
		padLen = 0
	}
	b.WriteString(statusBarStyle.Width(w).Render(keys + strings.Repeat(" ", padLen)))

	return b.String()
}

func (m Model) renderHeader(b *strings.Builder, w int) {
	active := 0
	totalConns := 0
	for _, p := range m.config.Pods {
		if !m.exited[p.Name] {
			active++
		}
		totalConns += len(m.peers[p.Name])
	}

	ts := ""
	if !m.timestamp.IsZero() {
		ts = m.timestamp.Format("15:04:05Z")
	}

	target := fmt.Sprintf("%s/%s/%s", m.config.Namespace, m.config.Target.Kind, m.config.Target.Name)
	filterLabel := m.config.Filter.FilterSummary()
	var headerText string
	if m.timestamp.IsZero() {
		headerText = fmt.Sprintf("  ◎ ocellus  %s  %s   %d pods   loading…",
			target, filterLabel, len(m.config.Pods))
	} else {
		headerText = fmt.Sprintf("  ◎ ocellus  %s  %s   %d/%d active   %d connections   %s",
			target, filterLabel, active, len(m.config.Pods), totalConns, ts)
	}
	b.WriteString(headerStyle.Width(w).Render(headerText))
	b.WriteString("\n")

	b.WriteString(dividerStyle.Render(strings.Repeat("─", w)))
	b.WriteString("\n")
}

func (m Model) viewPodList(w int) string {
	var b strings.Builder

	m.renderHeader(&b, w)

	// Compute max pod name width for alignment.
	maxNameW := 0
	for _, p := range m.config.Pods {
		name := p.Name
		if m.exited[p.Name] {
			name += " (exited)"
		}
		if len(name) > maxNameW {
			maxNameW = len(name)
		}
	}

	// Pod table rows (scrollable).
	paneH := m.podPaneHeight()
	start := m.podScroll
	end := start + paneH
	if end > len(m.config.Pods) {
		end = len(m.config.Pods)
	}

	for i := start; i < end; i++ {
		p := m.config.Pods[i]
		peerCount := len(m.peers[p.Name])

		name := p.Name
		if m.exited[p.Name] {
			name += " (exited)"
		}

		var totalBytes uint64
		for _, peer := range m.peers[p.Name] {
			totalBytes += peer.Bytes
		}

		var countText string
		switch {
		case m.timestamp.IsZero():
			countText = "…"
		case peerCount == 1:
			countText = "1 peer"
			if totalBytes > 0 {
				countText += "  " + format.Bytes(totalBytes)
			}
		default:
			countText = fmt.Sprintf("%d peers", peerCount)
			if totalBytes > 0 {
				countText += "  " + format.Bytes(totalBytes)
			}
		}

		if i == m.cursor {
			// Selected row: plain text with highlight background, no inline ANSI.
			icon := "●"
			line := fmt.Sprintf("  %s %-*s  %s", icon, maxNameW, name, countText)
			b.WriteString(selectedRowStyle.Width(w).Render(line))
		} else {
			icon := activeIcon.String()
			if m.exited[p.Name] {
				icon = exitedIcon.String()
			}
			var countStr string
			switch {
			case m.timestamp.IsZero():
				countStr = peerCountStyle.Render(countText)
			case peerCount > 0:
				countStr = peerCountActiveStyle.Render(countText)
			default:
				countStr = peerCountStyle.Render(countText)
			}
			line := fmt.Sprintf("  %s %-*s  %s", icon, maxNameW, name, countStr)
			b.WriteString(rowStyle.Width(w).Render(line))
		}
		b.WriteString("\n")
	}

	// Fill remaining space.
	visiblePods := end - start
	usedLines := 2 + visiblePods + 1 + 1 // header + divider + visible pods + bottom divider + status
	for i := usedLines; i < m.height; i++ {
		b.WriteString("\n")
	}

	b.WriteString(dividerStyle.Render(strings.Repeat("─", w)))
	b.WriteString("\n")

	// Status bar.
	var statusIndicator string
	switch {
	case len(m.lastErrors) > 0:
		statusIndicator = errorStyle.Render("✘ " + errorSummary(m.lastErrors))
	case m.paused:
		statusIndicator = pausedStyle.Render("● paused")
	case m.polling:
		statusIndicator = pollingStyle.Render("◉ polling")
	}
	keys := fmt.Sprintf("  %s quit  %s navigate  %s select  %s next active  %s pause  %s help",
		statusBarKeyStyle.Render("q"),
		statusBarKeyStyle.Render("j/k"),
		statusBarKeyStyle.Render("enter"),
		statusBarKeyStyle.Render("tab"),
		statusBarKeyStyle.Render("p"),
		statusBarKeyStyle.Render("?"))
	padLen := w - lipgloss.Width(keys) - lipgloss.Width(statusIndicator) - 2
	if padLen < 0 {
		padLen = 0
	}
	statusText := keys + strings.Repeat(" ", padLen) + statusIndicator
	b.WriteString(statusBarStyle.Width(w).Render(statusText))

	return b.String()
}

func (m Model) viewPeerList(w int) string {
	var b strings.Builder

	m.renderHeader(&b, w)

	if len(m.config.Pods) == 0 || m.cursor >= len(m.config.Pods) {
		b.WriteString("  (no pods)\n")
		return b.String()
	}

	selected := m.config.Pods[m.cursor]
	allPeers := m.peers[selected.Name]
	filtered := m.filteredPeers(allPeers)
	peers := sortPeers(filtered, m.sortField, m.sortReverse)

	// Subheader.
	countLabel := fmt.Sprintf("%d connections", len(peers))
	if m.searchQuery != "" && len(peers) != len(allPeers) {
		countLabel = fmt.Sprintf("%d/%d connections", len(peers), len(allPeers))
	}
	subheader := fmt.Sprintf("Peers for %s:   %s",
		selected.Name,
		peerCountStyle.Render(countLabel))
	b.WriteString(detailHeaderStyle.Render(subheader))
	b.WriteString("\n")

	if len(peers) == 0 {
		b.WriteString(detailPeerStyle.Render("(none)"))
		b.WriteString("\n")
	} else {
		// Compute column widths.
		peerColW := len("Peer Address:Port")
		localColW := len("Local Address:Port")
		bytesColW := len("Rx/Tx")
		// Pre-compute bytes strings for width calculation.
		bytesStrs := make([]string, len(peers))
		for i, p := range peers {
			if len(p.Src) > peerColW {
				peerColW = len(p.Src)
			}
			local := fmt.Sprintf("%s:%d", selected.IP, p.DstPort)
			if len(local) > localColW {
				localColW = len(local)
			}
			var bs string
			if p.RxBytes > 0 || p.TxBytes > 0 {
				bs = format.Bytes(p.RxBytes) + "/" + format.Bytes(p.TxBytes)
			} else if p.Bytes > 0 {
				bs = format.Bytes(p.Bytes)
			}
			bytesStrs[i] = bs
			if len(bs) > bytesColW {
				bytesColW = len(bs)
			}
		}

		// Column header with sort indicators.
		arrow := "▲"
		if m.sortReverse {
			arrow = "▼"
		}
		styledArrow := " " + sortArrowStyle.Render(arrow)
		arrowW := lipgloss.Width(styledArrow)

		srcLabel := "Peer Address:Port"
		localLabel := "Local Address:Port"
		protoLabel := "Proto"
		stateLabel := "State"
		bytesLabel := "Rx/Tx"

		// Add arrow to active sort column.
		padSrc := peerColW
		padLocal := localColW
		switch m.sortField {
		case sortSrc:
			srcLabel += styledArrow
			padSrc = peerColW + arrowW
		case sortPort:
			localLabel += styledArrow
			padLocal = localColW + arrowW
		case sortProto:
			protoLabel += styledArrow
		case sortState:
			stateLabel += styledArrow
		case sortBytes:
			bytesLabel += styledArrow
		}

		// Pad labels. For labels with ANSI codes, we need to pad based on display width.
		srcPad := padSrc - lipgloss.Width(srcLabel)
		if srcPad > 0 {
			srcLabel += strings.Repeat(" ", srcPad)
		}
		localPad := padLocal - lipgloss.Width(localLabel)
		if localPad > 0 {
			localLabel += strings.Repeat(" ", localPad)
		}

		hdr := fmt.Sprintf("  %s  %s  %-5s  %-11s  %-*s",
			srcLabel, localLabel, protoLabel, stateLabel, bytesColW, bytesLabel)
		b.WriteString(columnHeaderStyle.Render(hdr))
		b.WriteString("\n")

		// Data rows (scrollable).
		paneH := m.peerPaneHeight()
		start := m.scroll
		if start > len(peers) {
			start = len(peers)
		}
		end := start + paneH
		if end > len(peers) {
			end = len(peers)
		}
		visible := peers[start:end]
		for vi, p := range visible {
			local := fmt.Sprintf("%s:%d", selected.IP, p.DstPort)

			// State with color.
			var stateStr string
			switch p.State {
			case "established":
				stateStr = stateEstablishedStyle.Render(fmt.Sprintf("%-11s", p.State))
			case "closing":
				stateStr = stateClosingStyle.Render(fmt.Sprintf("%-11s", p.State))
			default:
				stateStr = fmt.Sprintf("%-11s", p.State)
			}

			// Highlight search match in Src column.
			srcStr := highlightMatch(p.Src, m.searchQuery)
			srcPadding := peerColW - lipgloss.Width(srcStr)
			if srcPadding > 0 {
				srcStr += strings.Repeat(" ", srcPadding)
			}

			bytesStr := bytesStrs[start+vi]

			row := fmt.Sprintf("  %s  %-*s  %-5s  %s  %-*s",
				srcStr,
				localColW, local,
				p.Proto,
				stateStr,
				bytesColW, bytesStr)
			b.WriteString(detailPeerStyle.Render(row))
			b.WriteString("\n")
		}

		// Fill remaining space.
		for i := len(visible); i < paneH; i++ {
			b.WriteString("\n")
		}
	}

	b.WriteString(dividerStyle.Render(strings.Repeat("─", w)))
	b.WriteString("\n")

	// Status bar.
	if m.searching {
		searchText := fmt.Sprintf("  /%s_", m.searchQuery)
		padLen := w - lipgloss.Width(searchText) - 2
		if padLen < 0 {
			padLen = 0
		}
		b.WriteString(searchBarStyle.Width(w).Render(searchText + strings.Repeat(" ", padLen)))
	} else {
		var statusIndicator string
		switch {
		case len(m.lastErrors) > 0:
			statusIndicator = errorStyle.Render("✘ " + errorSummary(m.lastErrors))
		case m.paused:
			statusIndicator = pausedStyle.Render("● paused")
		case m.polling:
			statusIndicator = pollingStyle.Render("◉ polling")
		}
		scrollInfo := ""
		maxScroll := m.maxScroll()
		if maxScroll > 0 {
			scrollInfo = fmt.Sprintf("  [%d/%d]", m.scroll+1, maxScroll+1)
		}

		keys := fmt.Sprintf("  %s back  %s scroll  %s sort  %s search  %s pause  %s quit%s",
			statusBarKeyStyle.Render("esc"),
			statusBarKeyStyle.Render("j/k"),
			statusBarKeyStyle.Render("s/S"),
			statusBarKeyStyle.Render("/"),
			statusBarKeyStyle.Render("p"),
			statusBarKeyStyle.Render("q"),
			scrollInfo)
		padLen := w - lipgloss.Width(keys) - lipgloss.Width(statusIndicator) - 2
		if padLen < 0 {
			padLen = 0
		}
		statusText := keys + strings.Repeat(" ", padLen) + statusIndicator
		b.WriteString(statusBarStyle.Width(w).Render(statusText))
	}

	return b.String()
}
