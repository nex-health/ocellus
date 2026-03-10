package tui

import (
	"fmt"
	"maps"
	"sort"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/nex-health/ocellus/internal/capture"
	"github.com/nex-health/ocellus/internal/cilium"
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
		newM, cmd := m.handlePollResult(msg)
		return newM, cmd

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
func (m Model) podPaneHeight() int {
	return max(m.height-4, 1)
}

// clampPodScroll ensures podScroll keeps the cursor visible.
func (m *Model) clampPodScroll() {
	paneH := m.podPaneHeight()
	if m.cursor < m.podScroll {
		m.podScroll = m.cursor
	}
	if m.cursor >= m.podScroll+paneH {
		m.podScroll = m.cursor - paneH + 1
	}
	maxScroll := max(len(m.config.Pods)-paneH, 0)
	if m.podScroll > maxScroll {
		m.podScroll = maxScroll
	}
	if m.podScroll < 0 {
		m.podScroll = 0
	}
}

// peerPaneHeight returns lines available for peer data rows in the peer view.
func (m Model) peerPaneHeight() int {
	fixed := 1 + 1 + 1 + 1 + 1 + 1 // header + divider + subheader + col header + bottom divider + status
	return max(m.height-fixed, 1)
}

// maxScroll returns the maximum valid scroll value for the peer view.
func (m Model) maxScroll() int {
	peers := m.selectedPeers()
	return max(len(peers)-m.peerPaneHeight(), 0)
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
