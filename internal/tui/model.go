package tui

import (
	"fmt"
	"maps"
	"sort"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/nex-health/ocellus/internal/capture"
	"github.com/nex-health/ocellus/internal/cilium"
	"github.com/nex-health/ocellus/internal/format"
	"github.com/nex-health/ocellus/internal/k8s"
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
	sortDir
	sortState
	sortBytes
	sortFieldCount // sentinel for cycling
)

type stateFilter int

const (
	stateAll stateFilter = iota
	stateEstablished
	stateClosing
	stateFilterCount // sentinel for cycling
)

func (f stateFilter) String() string {
	switch f {
	case stateEstablished:
		return "established"
	case stateClosing:
		return "closing"
	default:
		return "all"
	}
}

type protoFilter int

const (
	protoAll protoFilter = iota
	protoTCP
	protoUDP
	protoFilterCount // sentinel for cycling
)

func (f protoFilter) String() string {
	switch f {
	case protoTCP:
		return "TCP"
	case protoUDP:
		return "UDP"
	default:
		return "all"
	}
}

type dirFilter int

const (
	dirAll dirFilter = iota
	dirIn
	dirOut
	dirFilterCount // sentinel for cycling
)

func (f dirFilter) String() string {
	switch f {
	case dirIn:
		return "IN"
	case dirOut:
		return "OUT"
	default:
		return "all"
	}
}

type ipVerFilter int

const (
	ipVerAll ipVerFilter = iota
	ipVer4
	ipVer6
	ipVerFilterCount // sentinel for cycling
)

func (f ipVerFilter) String() string {
	switch f {
	case ipVer4:
		return "v4"
	case ipVer6:
		return "v6"
	default:
		return "all"
	}
}

// Messages
type tickMsg struct{}

type pollResultMsg struct {
	peers     map[string][]cilium.Peer
	exited    map[string]bool
	pods      []k8s.PodInfo
	timestamp time.Time
	errors    []string
}

type pendingKeyTimeoutMsg struct{}

// Config holds the parameters for the TUI.
type Config struct {
	Filter       cilium.Filter
	Namespace    string
	Context      string // kubeconfig context name
	Target       k8s.Target
	Interval     time.Duration
	PollTimeout  time.Duration // 0 = no timeout
	Client       ClusterClient
	Source       cilium.ConntrackSource
	Pods         []k8s.PodInfo
	OutputFormat string // capture format: "jsonl", "json", "csv", "text"
	OutputFile   string // capture file path (empty = auto-generated)
}

// Model is the Bubble Tea model for the ocellus TUI.
type Model struct {
	config         Config
	width          int
	height         int
	mode           viewMode
	cursor         int // selected pod index
	podScroll      int // scroll offset in pod list
	scroll         int // scroll offset in peer view
	peers          map[string][]cilium.Peer
	exited         map[string]bool
	timestamp      time.Time
	polling        bool
	paused         bool // polling paused due to user navigation
	quitting       bool
	sortField      sortField
	sortReverse    bool
	stateFilter    stateFilter
	protoFilter    protoFilter
	dirFilter      dirFilter
	ipVerFilter    ipVerFilter
	searching      bool
	searchQuery    string
	showHelp       bool
	lastErrors     []string
	pendingKey     string // for multi-key chords like "gg"
	prevTotalBytes uint64
	bytesPerSec    uint64
	recorder       *capture.Recorder
	dumpStatus     string    // status message shown briefly after dump
	dumpStatusT    time.Time // when dumpStatus was set
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

// CloseRecorder closes the recorder if one exists.
func (m Model) CloseRecorder() {
	if m.recorder != nil {
		m.recorder.Close()
	}
}

// CaptureFilePath returns the capture file path if a recorder was used.
func (m Model) CaptureFilePath() string {
	if m.recorder != nil {
		return m.recorder.Path()
	}
	return ""
}

// ensureRecorder creates the recorder if it doesn't exist.
func (m *Model) ensureRecorder() error {
	if m.recorder != nil {
		return nil
	}
	format := m.config.OutputFormat
	if format == "" {
		format = "jsonl"
	}
	f, err := capture.NewFormatter(format)
	if err != nil {
		return err
	}
	path := m.config.OutputFile
	if path == "" {
		path = fmt.Sprintf("ocellus-%s.%s", time.Now().Format("2006-01-02T15-04-05"), format)
	}
	w, err := capture.NewFileWriter(path)
	if err != nil {
		return err
	}
	m.recorder = capture.NewRecorder(f, w)
	return nil
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
		if _, after, ok := strings.Cut(e, ": "); ok {
			reason = after
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
	maps.Copy(exitedCopy, m.exited)
	return pollCmd(pollConfig{
		client:    m.config.Client,
		source:    m.config.Source,
		namespace: m.config.Namespace,
		target:    m.config.Target,
		filter:    m.config.Filter,
		pods:      m.pollTargets(),
		exited:    exitedCopy,
		timeout:   m.config.PollTimeout,
	})
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
		m.lastErrors = msg.errors
		maps.Copy(m.peers, msg.peers)
		for name := range msg.exited {
			m.exited[name] = true
		}
		// Refresh the pod list so new pods appear (scaling, rollouts, restarts).
		if msg.pods != nil {
			m.config.Pods = msg.pods
		}

		// Compute total bytes across all pods.
		var currentTotalBytes uint64
		for _, p := range m.config.Pods {
			for _, peer := range m.peers[p.Name] {
				currentTotalBytes += peer.Bytes
			}
		}

		// Calculate rate.
		if m.prevTotalBytes > 0 && !m.timestamp.IsZero() {
			elapsed := msg.timestamp.Sub(m.timestamp).Seconds()
			if elapsed > 0 && currentTotalBytes > m.prevTotalBytes {
				m.bytesPerSec = uint64(float64(currentTotalBytes-m.prevTotalBytes) / elapsed)
			} else {
				m.bytesPerSec = 0
			}
		}
		m.prevTotalBytes = currentTotalBytes
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
		case "d":
			if err := m.ensureRecorder(); err != nil {
				m.dumpStatus = fmt.Sprintf("dump error: %v", err)
				m.dumpStatusT = time.Now()
				return m, nil
			}
			snap := capture.Snapshot{
				Timestamp: m.timestamp,
				Pods:      m.peers,
				Exited:    m.exited,
				Errors:    m.lastErrors,
			}
			if err := m.recorder.DumpSnapshot(snap); err != nil {
				m.dumpStatus = fmt.Sprintf("dump error: %v", err)
			} else {
				m.dumpStatus = fmt.Sprintf("snapshot saved to %s", m.recorder.Path())
			}
			m.dumpStatusT = time.Now()
			return m, nil
		case "R":
			if err := m.ensureRecorder(); err != nil {
				m.dumpStatus = fmt.Sprintf("record error: %v", err)
				m.dumpStatusT = time.Now()
				return m, nil
			}
			m.recorder.SetContinuous(!m.recorder.IsContinuous())
			if m.recorder.IsContinuous() {
				m.dumpStatus = fmt.Sprintf("recording to %s", m.recorder.Path())
			} else {
				m.dumpStatus = "recording stopped"
			}
			m.dumpStatusT = time.Now()
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
	h := max(
		// header + divider + bottom divider + status
		m.height-4, 1)
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
	maxScroll := max(len(m.config.Pods)-paneH, 0)
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
	if m.searchQuery == "" && m.stateFilter == stateAll && m.protoFilter == protoAll && m.dirFilter == dirAll && m.ipVerFilter == ipVerAll {
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

// peerPaneHeight returns lines available for peer data rows in the peer view.
// Layout: header(1) + divider(1) + subheader(1) + column header(1) + [peer rows] + status(1)
func (m Model) peerPaneHeight() int {
	fixed := 1 + 1 + 1 + 1 + 1 + 1 // header + divider + subheader + col header + bottom divider + status
	h := max(m.height-fixed, 1)
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
	limit := max(len(peers)-m.peerPaneHeight(), 0)
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
		"  s             Cycle sort (src, port, proto, dir, state, bytes)",
		"  S             Toggle reverse sort",
		"  f             Cycle state filter (all, established, closing)",
		"  F             Cycle protocol filter (all, TCP, UDP)",
		"  D             Cycle direction filter (all, IN, OUT)",
		"  V             Cycle IP version filter (all, v4, v6)",
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
		"",
		"  d             Dump snapshot to file",
		"  R             Toggle continuous recording",
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
	padLen := max(w-lipgloss.Width(keys)-2, 0)
	b.WriteString(statusBarStyle.Width(w).Render(keys + strings.Repeat(" ", padLen)))

	return b.String()
}

func (m Model) renderHeader(b *strings.Builder, w int) {
	active := 0
	totalConns := 0
	var totalBytes uint64
	for _, p := range m.config.Pods {
		if !m.exited[p.Name] {
			active++
		}
		totalConns += len(m.peers[p.Name])
		for _, peer := range m.peers[p.Name] {
			totalBytes += peer.Bytes
		}
	}

	ts := ""
	if !m.timestamp.IsZero() {
		ts = m.timestamp.Format("15:04:05Z")
	}

	target := fmt.Sprintf("%s/%s/%s", m.config.Namespace, m.config.Target.Kind, m.config.Target.Name)
	filterLabel := m.config.Filter.FilterSummary()
	sep := headerDimStyle.Render(" │ ")

	var parts []string
	parts = append(parts, headerBrandStyle.Render("◎ ocellus"))
	if m.config.Context != "" {
		parts = append(parts, headerContextStyle.Render(m.config.Context))
	}
	parts = append(parts, headerTargetStyle.Render(target))
	if filterLabel != "" {
		parts = append(parts, headerDimStyle.Render(filterLabel))
	}

	if m.timestamp.IsZero() {
		parts = append(parts, headerDimStyle.Render(fmt.Sprintf("%d pods", len(m.config.Pods))))
		parts = append(parts, headerDimStyle.Render("loading…"))
	} else {
		parts = append(parts, headerStatsStyle.Render(fmt.Sprintf("%d/%d active", active, len(m.config.Pods))))
		parts = append(parts, headerDimStyle.Render(fmt.Sprintf("%d conn", totalConns)))
		if totalBytes > 0 {
			parts = append(parts, headerStatsStyle.Render(format.Bytes(totalBytes)))
		}
		if m.bytesPerSec > 0 {
			parts = append(parts, headerRateStyle.Render(fmt.Sprintf("%s/s", format.Bytes(m.bytesPerSec))))
		}
		parts = append(parts, headerDimStyle.Render(ts))
	}

	if m.recorder != nil && m.recorder.IsContinuous() {
		parts = append(parts, headerErrorStyle.Render("[REC]"))
	}

	headerText := "  " + strings.Join(parts, sep)
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
	end := min(start+paneH, len(m.config.Pods))

	for i := start; i < end; i++ {
		p := m.config.Pods[i]
		filtered := m.filteredPeers(m.peers[p.Name])
		peerCount := len(filtered)

		name := p.Name
		if m.exited[p.Name] {
			name += " (exited)"
		}

		var totalBytes uint64
		for _, peer := range filtered {
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
	if m.dumpStatus != "" && time.Since(m.dumpStatusT) < 5*time.Second {
		statusIndicator = headerDimStyle.Render(m.dumpStatus)
	} else {
		switch {
		case len(m.lastErrors) > 0:
			statusIndicator = errorStyle.Render("✘ " + errorSummary(m.lastErrors))
		case m.paused:
			statusIndicator = pausedStyle.Render("● paused")
		case m.polling:
			statusIndicator = pollingStyle.Render("◉ polling")
		}
	}
	keys := fmt.Sprintf("  %s quit  %s navigate  %s select  %s next active  %s pause  %s dump  %s record  %s help",
		statusBarKeyStyle.Render("q"),
		statusBarKeyStyle.Render("j/k"),
		statusBarKeyStyle.Render("enter"),
		statusBarKeyStyle.Render("tab"),
		statusBarKeyStyle.Render("p"),
		statusBarKeyStyle.Render("d"),
		statusBarKeyStyle.Render("R"),
		statusBarKeyStyle.Render("?"))
	padLen := max(w-lipgloss.Width(keys)-lipgloss.Width(statusIndicator)-2, 0)
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
	if len(peers) != len(allPeers) {
		countLabel = fmt.Sprintf("%d/%d connections", len(peers), len(allPeers))
	}
	subheader := fmt.Sprintf("Peers for %s:   %s",
		selected.Name,
		peerCountStyle.Render(countLabel))
	if m.stateFilter != stateAll {
		subheader += "  " + filterActiveStyle.Render(fmt.Sprintf("[state:%s]", m.stateFilter))
	}
	if m.protoFilter != protoAll {
		subheader += "  " + filterActiveStyle.Render(fmt.Sprintf("[proto:%s]", m.protoFilter))
	}
	if m.dirFilter != dirAll {
		subheader += "  " + filterActiveStyle.Render(fmt.Sprintf("[dir:%s]", m.dirFilter))
	}
	if m.ipVerFilter != ipVerAll {
		subheader += "  " + filterActiveStyle.Render(fmt.Sprintf("[ip:%s]", m.ipVerFilter))
	}
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
			switch {
			case p.RxBytes > 0 || p.TxBytes > 0:
				bs = format.Bytes(p.RxBytes) + "/" + format.Bytes(p.TxBytes)
			case p.Bytes > 0:
				bs = format.Bytes(p.Bytes)
			default:
				bs = "—"
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
		dirLabel := "Dir"
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
		case sortDir:
			dirLabel += styledArrow
		case sortState:
			stateLabel += styledArrow
		case sortBytes:
			bytesLabel += styledArrow
		}

		// Use padded widths (which include arrow width) for both header and data rows.
		srcPad := padSrc - lipgloss.Width(srcLabel)
		if srcPad > 0 {
			srcLabel += strings.Repeat(" ", srcPad)
		}
		localPad := padLocal - lipgloss.Width(localLabel)
		if localPad > 0 {
			localLabel += strings.Repeat(" ", localPad)
		}

		hdr := fmt.Sprintf("  %s  %s  %-5s  %-3s  %-11s  %-*s",
			srcLabel, localLabel, protoLabel, dirLabel, stateLabel, bytesColW, bytesLabel)
		b.WriteString(columnHeaderStyle.Render(hdr))
		b.WriteString("\n")

		// Data rows (scrollable).
		paneH := m.peerPaneHeight()
		start := min(m.scroll, len(peers))
		end := min(start+paneH, len(peers))
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
			srcPadding := padSrc - lipgloss.Width(srcStr)
			if srcPadding > 0 {
				srcStr += strings.Repeat(" ", srcPadding)
			}

			bytesStr := bytesStrs[start+vi]

			// Direction with color.
			var dirStr string
			switch p.Direction {
			case "in":
				dirStr = dirInStyle.Render(fmt.Sprintf("%-3s", "IN"))
			case "out":
				dirStr = dirOutStyle.Render(fmt.Sprintf("%-3s", "OUT"))
			default:
				dirStr = fmt.Sprintf("%-3s", p.Direction)
			}

			row := fmt.Sprintf("  %s  %-*s  %-5s  %s  %s  %-*s",
				srcStr,
				padLocal, local,
				p.Proto,
				dirStr,
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
		padLen := max(w-lipgloss.Width(searchText)-2, 0)
		b.WriteString(searchBarStyle.Width(w).Render(searchText + strings.Repeat(" ", padLen)))
	} else {
		var statusIndicator string
		if m.dumpStatus != "" && time.Since(m.dumpStatusT) < 5*time.Second {
			statusIndicator = headerDimStyle.Render(m.dumpStatus)
		} else {
			switch {
			case len(m.lastErrors) > 0:
				statusIndicator = errorStyle.Render("✘ " + errorSummary(m.lastErrors))
			case m.paused:
				statusIndicator = pausedStyle.Render("● paused")
			case m.polling:
				statusIndicator = pollingStyle.Render("◉ polling")
			}
		}
		scrollInfo := ""
		maxScroll := m.maxScroll()
		if maxScroll > 0 {
			scrollInfo = fmt.Sprintf("  [%d/%d]", m.scroll+1, maxScroll+1)
		}

		keys := fmt.Sprintf("  %s back  %s scroll  %s sort  %s filter  %s dir  %s ip  %s search  %s pause  %s quit%s",
			statusBarKeyStyle.Render("esc"),
			statusBarKeyStyle.Render("j/k"),
			statusBarKeyStyle.Render("s/S"),
			statusBarKeyStyle.Render("f/F"),
			statusBarKeyStyle.Render("D"),
			statusBarKeyStyle.Render("V"),
			statusBarKeyStyle.Render("/"),
			statusBarKeyStyle.Render("p"),
			statusBarKeyStyle.Render("q"),
			scrollInfo)
		padLen := max(w-lipgloss.Width(keys)-lipgloss.Width(statusIndicator)-2, 0)
		statusText := keys + strings.Repeat(" ", padLen) + statusIndicator
		b.WriteString(statusBarStyle.Width(w).Render(statusText))
	}

	return b.String()
}
