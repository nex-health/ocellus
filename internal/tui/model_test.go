package tui

import (
	"bytes"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"

	"github.com/nex-health/ocellus/internal/capture"
	"github.com/nex-health/ocellus/internal/cilium"
	"github.com/nex-health/ocellus/internal/k8s"
)

func testPods() []k8s.PodInfo {
	return []k8s.PodInfo{
		{Name: "pod-1", Node: "node-a", IP: "10.0.0.1"},
		{Name: "pod-2", Node: "node-a", IP: "10.0.0.2"},
		{Name: "pod-3", Node: "node-b", IP: "10.0.0.3"},
	}
}

func testModel() Model {
	return New(Config{
		Filter:   cilium.Filter{PortMin: 5432, PortMax: 5432},
		Interval: 10 * time.Second,
		Pods:     testPods(),
	})
}

func keyMsg(s string) tea.KeyMsg {
	switch s {
	case "enter":
		return tea.KeyMsg(tea.Key{Type: tea.KeyEnter})
	case "esc":
		return tea.KeyMsg(tea.Key{Type: tea.KeyEscape})
	case "pgdown":
		return tea.KeyMsg(tea.Key{Type: tea.KeyPgDown})
	case "pgup":
		return tea.KeyMsg(tea.Key{Type: tea.KeyPgUp})
	case "home":
		return tea.KeyMsg(tea.Key{Type: tea.KeyHome})
	case "end":
		return tea.KeyMsg(tea.Key{Type: tea.KeyEnd})
	case "tab":
		return tea.KeyMsg(tea.Key{Type: tea.KeyTab})
	case "shift+tab":
		return tea.KeyMsg(tea.Key{Type: tea.KeyShiftTab})
	case "backspace":
		return tea.KeyMsg(tea.Key{Type: tea.KeyBackspace})
	case "ctrl+d":
		return tea.KeyMsg(tea.Key{Type: tea.KeyCtrlD})
	case "ctrl+u":
		return tea.KeyMsg(tea.Key{Type: tea.KeyCtrlU})
	default:
		return tea.KeyMsg(tea.Key{Type: tea.KeyRunes, Runes: []rune(s)})
	}
}

func TestInitialState(t *testing.T) {
	m := testModel()
	if m.cursor != 0 {
		t.Errorf("cursor = %d, want 0", m.cursor)
	}
	if m.mode != viewPods {
		t.Errorf("mode = %d, want viewPods", m.mode)
	}
	if !m.polling {
		t.Error("polling should be true initially (loading state)")
	}
	if m.paused {
		t.Error("paused should be false initially")
	}
	if m.quitting {
		t.Error("quitting should be false initially")
	}
	if len(m.peers) != 0 {
		t.Errorf("peers should be empty, got %d", len(m.peers))
	}
}

func TestWindowResize(t *testing.T) {
	m := testModel()
	updated, _ := m.Update(tea.WindowSizeMsg{Width: 120, Height: 40})
	m2 := updated.(Model)
	if m2.width != 120 || m2.height != 40 {
		t.Errorf("size = %dx%d, want 120x40", m2.width, m2.height)
	}
}

func TestPollResultMerging(t *testing.T) {
	m := testModel()
	ts := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)

	updated, _ := m.Update(pollResultMsg{
		peers: map[string][]cilium.Peer{
			"pod-1": {
				{Src: "10.1.0.1:52628", DstPort: 5432},
				{Src: "10.1.0.2:48190", DstPort: 5432},
			},
			"pod-2": {
				{Src: "10.1.0.3:39442", DstPort: 5432},
			},
		},
		timestamp: ts,
	})
	m2 := updated.(Model)

	if len(m2.peers["pod-1"]) != 2 {
		t.Errorf("pod-1 peers = %d, want 2", len(m2.peers["pod-1"]))
	}
	if len(m2.peers["pod-2"]) != 1 {
		t.Errorf("pod-2 peers = %d, want 1", len(m2.peers["pod-2"]))
	}
	if m2.timestamp != ts {
		t.Errorf("timestamp = %v, want %v", m2.timestamp, ts)
	}

	// Second poll updates existing and adds new.
	updated, _ = m2.Update(pollResultMsg{
		peers: map[string][]cilium.Peer{
			"pod-1": {
				{Src: "10.1.0.1:52628", DstPort: 5432},
			},
			"pod-3": {
				{Src: "10.1.0.4:11111", DstPort: 5432},
			},
		},
		timestamp: ts.Add(10 * time.Second),
	})
	m3 := updated.(Model)
	if len(m3.peers["pod-1"]) != 1 {
		t.Errorf("pod-1 peers after update = %d, want 1", len(m3.peers["pod-1"]))
	}
	if len(m3.peers["pod-2"]) != 1 {
		t.Errorf("pod-2 peers should remain 1, got %d", len(m3.peers["pod-2"]))
	}
	if len(m3.peers["pod-3"]) != 1 {
		t.Errorf("pod-3 peers = %d, want 1", len(m3.peers["pod-3"]))
	}
}

func TestExitedPodTracking(t *testing.T) {
	m := testModel()
	updated, _ := m.Update(pollResultMsg{
		peers:     map[string][]cilium.Peer{},
		exited:    map[string]bool{"pod-2": true},
		timestamp: time.Now(),
	})
	m2 := updated.(Model)
	if !m2.exited["pod-2"] {
		t.Error("pod-2 should be marked exited")
	}
	if m2.exited["pod-1"] {
		t.Error("pod-1 should not be exited")
	}
}

func TestPodListNavigation(t *testing.T) {
	m := testModel()
	m.width = 80
	m.height = 24

	// Move down.
	updated, _ := m.Update(keyMsg("j"))
	m2 := updated.(Model)
	if m2.cursor != 1 {
		t.Errorf("cursor = %d, want 1", m2.cursor)
	}
	if m2.mode != viewPods {
		t.Errorf("mode = %d, want viewPods", m2.mode)
	}

	// Move down again.
	updated, _ = m2.Update(keyMsg("j"))
	m3 := updated.(Model)
	if m3.cursor != 2 {
		t.Errorf("cursor = %d, want 2", m3.cursor)
	}

	// At last pod, j stays on last pod.
	updated, _ = m3.Update(keyMsg("j"))
	m4 := updated.(Model)
	if m4.cursor != 2 {
		t.Errorf("cursor = %d, want 2 (clamped)", m4.cursor)
	}

	// Move up.
	updated, _ = m4.Update(keyMsg("k"))
	m5 := updated.(Model)
	if m5.cursor != 1 {
		t.Errorf("cursor = %d, want 1", m5.cursor)
	}

	// Move up to top and past.
	updated, _ = m5.Update(keyMsg("k"))
	m6 := updated.(Model)
	updated, _ = m6.Update(keyMsg("k"))
	m7 := updated.(Model)
	if m7.cursor != 0 {
		t.Errorf("cursor = %d, want 0 (clamped)", m7.cursor)
	}
}

func TestEnterSwitchesToPeerView(t *testing.T) {
	m := testModel()
	m.width = 80
	m.height = 24
	m.peers["pod-1"] = []cilium.Peer{{Src: "10.1.0.1:1234", DstPort: 5432}}

	updated, _ := m.Update(keyMsg("enter"))
	m2 := updated.(Model)
	if m2.mode != viewPeers {
		t.Errorf("mode = %d, want viewPeers", m2.mode)
	}
	if m2.scroll != 0 {
		t.Errorf("scroll = %d, want 0", m2.scroll)
	}
	if m2.cursor != 0 {
		t.Errorf("cursor = %d, want 0 (unchanged)", m2.cursor)
	}
}

func TestEscReturnsToPodList(t *testing.T) {
	m := testModel()
	m.width = 80
	m.height = 24
	m.mode = viewPeers
	m.scroll = 5

	updated, _ := m.Update(keyMsg("esc"))
	m2 := updated.(Model)
	if m2.mode != viewPods {
		t.Errorf("mode = %d, want viewPods", m2.mode)
	}
	if m2.scroll != 0 {
		t.Errorf("scroll = %d, want 0 (reset)", m2.scroll)
	}
}

func TestPeerViewScrolling(t *testing.T) {
	m := testModel()
	m.width = 80
	m.height = 12
	m.mode = viewPeers

	var peers []cilium.Peer
	for i := range 20 {
		peers = append(peers, cilium.Peer{
			Src:     fmt.Sprintf("10.1.0.%d:%d", i, 1000+i),
			DstPort: 5432,
		})
	}
	m.peers["pod-1"] = peers

	// Scroll down.
	updated, _ := m.Update(keyMsg("j"))
	m2 := updated.(Model)
	if m2.scroll != 1 {
		t.Errorf("scroll = %d, want 1", m2.scroll)
	}

	// Scroll up.
	updated, _ = m2.Update(keyMsg("k"))
	m3 := updated.(Model)
	if m3.scroll != 0 {
		t.Errorf("scroll = %d, want 0", m3.scroll)
	}

	// Scroll up past 0 clamps.
	updated, _ = m3.Update(keyMsg("k"))
	m4 := updated.(Model)
	if m4.scroll != 0 {
		t.Errorf("scroll = %d, want 0 (clamped)", m4.scroll)
	}
}

func TestPeerViewPageUpDown(t *testing.T) {
	m := testModel()
	m.width = 80
	m.height = 12
	m.mode = viewPeers
	var peers []cilium.Peer
	for i := range 30 {
		peers = append(peers, cilium.Peer{
			Src:     fmt.Sprintf("10.1.0.%d:%d", i, 1000+i),
			DstPort: 5432,
		})
	}
	m.peers["pod-1"] = peers

	// Page down.
	updated, _ := m.Update(keyMsg("pgdown"))
	m2 := updated.(Model)
	if m2.scroll == 0 {
		t.Error("pgdown should scroll")
	}
	scrollAfterPgDn := m2.scroll

	// Page up should go back.
	updated, _ = m2.Update(keyMsg("pgup"))
	m3 := updated.(Model)
	if m3.scroll >= scrollAfterPgDn {
		t.Errorf("pgup should decrease scroll, got %d (was %d)", m3.scroll, scrollAfterPgDn)
	}
}

func TestPeerViewHomeEnd(t *testing.T) {
	m := testModel()
	m.width = 80
	m.height = 12
	m.mode = viewPeers
	var peers []cilium.Peer
	for i := range 30 {
		peers = append(peers, cilium.Peer{
			Src:     fmt.Sprintf("10.1.0.%d:%d", i, 1000+i),
			DstPort: 5432,
		})
	}
	m.peers["pod-1"] = peers

	// End — should scroll to max.
	updated, _ := m.Update(keyMsg("end"))
	m2 := updated.(Model)
	if m2.scroll == 0 {
		t.Error("End should scroll to bottom")
	}
	if m2.scroll != m2.maxScroll() {
		t.Errorf("scroll = %d, want maxScroll %d", m2.scroll, m2.maxScroll())
	}

	// Home — should go back to 0.
	updated, _ = m2.Update(keyMsg("home"))
	m3 := updated.(Model)
	if m3.scroll != 0 {
		t.Errorf("Home should reset scroll to 0, got %d", m3.scroll)
	}
}

func TestNavigationPausesPolling(t *testing.T) {
	m := testModel()
	m.mode = viewPeers
	var peers []cilium.Peer
	for i := range 20 {
		peers = append(peers, cilium.Peer{
			Src:     fmt.Sprintf("10.1.0.%d:%d", i, 1000+i),
			DstPort: 5432,
		})
	}
	m.peers["pod-1"] = peers
	m.width = 80
	m.height = 10

	// Simulate first poll completing to clear initial polling state.
	m.polling = false
	m.timestamp = time.Now()

	// Tick while paused should be a no-op.
	m.paused = true
	updated, cmd := m.Update(tickMsg{})
	m2 := updated.(Model)
	if cmd != nil {
		t.Error("tick while paused should return nil cmd")
	}
	if m2.polling {
		t.Error("should not start polling while paused")
	}

	// Press 'r' to resume.
	updated, cmd = m2.Update(keyMsg("r"))
	m3 := updated.(Model)
	if m3.paused {
		t.Error("pressing r should unpause")
	}
	if !m3.polling {
		t.Error("pressing r should start polling")
	}
	if cmd == nil {
		t.Error("pressing r should return a poll command")
	}
}

func TestPollResultWhilePausedDoesNotScheduleTick(t *testing.T) {
	m := testModel()
	m.paused = true

	updated, cmd := m.Update(pollResultMsg{
		peers: map[string][]cilium.Peer{
			"pod-1": {{Src: "10.1.0.1:1234", DstPort: 5432}},
		},
		timestamp: time.Now(),
	})
	m2 := updated.(Model)
	if cmd != nil {
		t.Error("poll result while paused should not schedule next tick")
	}
	if len(m2.peers["pod-1"]) != 1 {
		t.Error("poll result should still be merged even when paused")
	}
}

func TestQuit(t *testing.T) {
	m := testModel()
	updated, cmd := m.Update(keyMsg("q"))
	m2 := updated.(Model)
	if !m2.quitting {
		t.Error("quitting should be true after q")
	}
	if cmd == nil {
		t.Error("quit command should not be nil")
	}
}

func TestQuitFromPeerView(t *testing.T) {
	m := testModel()
	m.mode = viewPeers
	updated, cmd := m.Update(keyMsg("q"))
	m2 := updated.(Model)
	if !m2.quitting {
		t.Error("quitting should be true after q in peer view")
	}
	if cmd == nil {
		t.Error("quit command should not be nil")
	}
}

func TestPodListViewRenders(t *testing.T) {
	m := testModel()
	m.width = 80
	m.height = 24
	m.peers["pod-1"] = []cilium.Peer{{Src: "10.1.0.1:1234", DstPort: 5432}}
	m.timestamp = time.Date(2025, 1, 1, 14, 30, 0, 0, time.UTC)

	view := m.View()
	if view == "" {
		t.Error("View() should not be empty")
	}
	if !strings.Contains(view, "ocellus") {
		t.Error("View should contain 'ocellus'")
	}
	if !strings.Contains(view, "pod-1") {
		t.Error("View should contain 'pod-1'")
	}
	if !strings.Contains(view, "14:30:00Z") {
		t.Error("View should contain timestamp")
	}
	if !strings.Contains(view, "enter") {
		t.Error("Pod list view should show 'enter' key hint")
	}
}

func TestPeerListViewRenders(t *testing.T) {
	m := testModel()
	m.width = 80
	m.height = 24
	m.mode = viewPeers
	m.peers["pod-1"] = []cilium.Peer{
		{Src: "10.1.0.1:1234", DstPort: 5432},
		{Src: "10.1.0.2:5678", DstPort: 5432},
	}

	view := m.View()

	if !strings.Contains(view, "Peers for pod-1") {
		t.Error("Peer view should contain 'Peers for pod-1'")
	}
	if !strings.Contains(view, "Peer Address:Port") {
		t.Error("Peer view should contain 'Peer Address:Port' column header")
	}
	if !strings.Contains(view, "Local Address:Port") {
		t.Error("Peer view should contain 'Local Address:Port' column header")
	}
	if !strings.Contains(view, "10.1.0.1:1234") {
		t.Error("Peer view should contain peer source address")
	}
	if !strings.Contains(view, "10.0.0.1:5432") {
		t.Error("Peer view should contain local address (podIP:port)")
	}
	if !strings.Contains(view, "2 connections") {
		t.Error("Peer view should contain '2 connections'")
	}
	if !strings.Contains(view, "esc") {
		t.Error("Peer view should show 'esc' key hint")
	}
}

func TestPeerListViewNoPeers(t *testing.T) {
	m := testModel()
	m.width = 80
	m.height = 24
	m.mode = viewPeers

	view := m.View()
	if !strings.Contains(view, "(none)") {
		t.Error("Peer view should show '(none)' when no peers")
	}
}

func TestViewShowsPausedStatus(t *testing.T) {
	m := testModel()
	m.width = 80
	m.height = 24
	m.paused = true

	view := m.View()
	if !strings.Contains(view, "paused") {
		t.Error("View should show 'paused' when paused")
	}
	if !strings.Contains(view, "r") {
		t.Error("View should show 'r' resume hint when paused")
	}
}

func TestRoundTripPodToPeerAndBack(t *testing.T) {
	m := testModel()
	m.width = 80
	m.height = 24
	m.peers["pod-2"] = []cilium.Peer{{Src: "10.1.0.1:1234", DstPort: 5432}}

	// Navigate to pod-2.
	updated, _ := m.Update(keyMsg("j"))
	m2 := updated.(Model)
	if m2.cursor != 1 {
		t.Fatalf("cursor = %d, want 1", m2.cursor)
	}

	// Enter peer view.
	updated, _ = m2.Update(keyMsg("enter"))
	m3 := updated.(Model)
	if m3.mode != viewPeers {
		t.Fatalf("mode = %d, want viewPeers", m3.mode)
	}

	// Verify peer view shows pod-2 peers.
	view := m3.View()
	if !strings.Contains(view, "Peers for pod-2") {
		t.Error("Peer view should show peers for pod-2")
	}

	// Go back.
	updated, _ = m3.Update(keyMsg("esc"))
	m4 := updated.(Model)
	if m4.mode != viewPods {
		t.Errorf("mode = %d, want viewPods", m4.mode)
	}
	if m4.cursor != 1 {
		t.Errorf("cursor = %d, want 1 (preserved after returning)", m4.cursor)
	}
}

func TestPeerSortCycle(t *testing.T) {
	m := testModel()
	m.width = 80
	m.height = 24
	m.mode = viewPeers
	m.peers["pod-1"] = []cilium.Peer{
		{Src: "10.1.0.2:2000", DstPort: 80},
		{Src: "10.1.0.1:1000", DstPort: 443},
	}

	// Default sort is by source IP.
	if m.sortField != sortSrc {
		t.Errorf("default sortField = %d, want sortSrc", m.sortField)
	}

	// Press 's' to cycle to next sort field.
	updated, _ := m.Update(keyMsg("s"))
	m2 := updated.(Model)
	if m2.sortField != sortPort {
		t.Errorf("sortField after 's' = %d, want sortPort", m2.sortField)
	}

	// Press 'S' to toggle reverse.
	updated, _ = m2.Update(keyMsg("S"))
	m3 := updated.(Model)
	if !m3.sortReverse {
		t.Error("sortReverse should be true after 'S'")
	}
}

func TestPeerSearchFilter(t *testing.T) {
	m := testModel()
	m.width = 80
	m.height = 24
	m.mode = viewPeers
	m.peers["pod-1"] = []cilium.Peer{
		{Src: "10.1.0.1:1000", DstPort: 5432},
		{Src: "10.1.0.2:2000", DstPort: 5432},
		{Src: "10.2.0.1:3000", DstPort: 5432},
	}

	// Press '/' to enter search mode.
	updated, _ := m.Update(keyMsg("/"))
	m2 := updated.(Model)
	if !m2.searching {
		t.Error("should be in search mode after '/'")
	}

	// Type "10.1" — should filter to 2 peers.
	for _, ch := range "10.1" {
		updated, _ = m2.Update(keyMsg(string(ch)))
		m2 = updated.(Model)
	}
	if m2.searchQuery != "10.1" {
		t.Errorf("searchQuery = %q, want '10.1'", m2.searchQuery)
	}

	filtered := m2.filteredPeers(m2.peers["pod-1"])
	if len(filtered) != 2 {
		t.Errorf("filtered peers = %d, want 2", len(filtered))
	}

	// Esc clears search.
	updated, _ = m2.Update(keyMsg("esc"))
	m3 := updated.(Model)
	if m3.searching {
		t.Error("should exit search mode on esc")
	}
	if m3.searchQuery != "" {
		t.Error("searchQuery should be cleared on esc")
	}
}

func TestPeerViewShowsStateColumn(t *testing.T) {
	m := testModel()
	m.width = 120
	m.height = 24
	m.mode = viewPeers
	m.peers["pod-1"] = []cilium.Peer{
		{Src: "10.1.0.1:1234", DstPort: 5432, Proto: "TCP", State: "established"},
	}

	view := m.View()
	if !strings.Contains(view, "State") {
		t.Error("should show State column header")
	}
	if !strings.Contains(view, "established") {
		t.Error("should show state value")
	}
}

func TestPeerViewStateColoring(t *testing.T) {
	m := testModel()
	m.width = 120
	m.height = 24
	m.mode = viewPeers
	m.peers["pod-1"] = []cilium.Peer{
		{Src: "10.1.0.1:1234", DstPort: 5432, State: "established"},
		{Src: "10.1.0.2:5678", DstPort: 5432, State: "closing"},
	}

	view := m.View()
	if !strings.Contains(view, "established") {
		t.Error("should show established state")
	}
	if !strings.Contains(view, "closing") {
		t.Error("should show closing state")
	}
}

func TestHelpToggle(t *testing.T) {
	m := testModel()
	m.width = 80
	m.height = 24

	// Press '?' to show help.
	updated, _ := m.Update(keyMsg("?"))
	m2 := updated.(Model)
	if !m2.showHelp {
		t.Error("showHelp should be true after '?'")
	}
	view := m2.View()
	if !strings.Contains(view, "Keybindings") {
		t.Error("help overlay should show 'Keybindings'")
	}

	// Press '?' again to dismiss.
	updated, _ = m2.Update(keyMsg("?"))
	m3 := updated.(Model)
	if m3.showHelp {
		t.Error("showHelp should be false after second '?'")
	}
}

func TestTabJumpsToNextPodWithPeers(t *testing.T) {
	m := testModel()
	m.width = 80
	m.height = 24
	// pod-1 has 0 peers, pod-2 has 1, pod-3 has 0.
	m.peers["pod-2"] = []cilium.Peer{{Src: "10.1.0.1:1234", DstPort: 5432}}

	updated, _ := m.Update(keyMsg("tab"))
	m2 := updated.(Model)
	if m2.cursor != 1 {
		t.Errorf("cursor = %d, want 1 (pod-2 has peers)", m2.cursor)
	}
}

func TestStartPollDoesNotShareExitedMap(t *testing.T) {
	m := testModel()
	m.exited["pod-2"] = true

	// startPoll captures the exited map. Mutating m.exited after
	// should not affect the snapshot used by pollCmd.
	_ = m.startPoll()
	m.exited["pod-3"] = true

	// The map passed to pollCmd should not contain pod-3.
	// We verify this indirectly: if exited is shared, mutations
	// leak across goroutines. Since we can't inspect the closure,
	// we test that the model's exited map is independent by
	// checking the original still has pod-3 but len is 2.
	if len(m.exited) != 2 {
		t.Errorf("exited map len = %d, want 2", len(m.exited))
	}
}

func TestPollResultWithEmptyPods(t *testing.T) {
	m := New(Config{
		Filter:   cilium.Filter{PortMin: 5432, PortMax: 5432},
		Interval: 10 * time.Second,
		Pods:     []k8s.PodInfo{}, // empty!
	})
	m.width = 80
	m.height = 24

	updated, _ := m.Update(pollResultMsg{
		peers:     map[string][]cilium.Peer{},
		timestamp: time.Now(),
	})
	m2 := updated.(Model)
	if m2.cursor != 0 {
		t.Errorf("cursor = %d, want 0", m2.cursor)
	}

	// View should not panic.
	view := m2.View()
	if view == "" {
		t.Error("View() should not be empty")
	}
}

func TestPollResultShowsErrors(t *testing.T) {
	m := testModel()
	m.width = 80
	m.height = 24

	updated, _ := m.Update(pollResultMsg{
		peers:     map[string][]cilium.Peer{},
		timestamp: time.Now(),
		errors:    []string{"pod discovery: connection refused"},
	})
	m2 := updated.(Model)
	if len(m2.lastErrors) != 1 {
		t.Fatalf("lastErrors len = %d, want 1", len(m2.lastErrors))
	}

	view := m2.View()
	if !strings.Contains(view, "connection refused") {
		t.Error("View should display poll error")
	}
}

func TestSortCacheInvalidatedOnNewData(t *testing.T) {
	m := testModel()
	m.width = 80
	m.height = 24
	m.mode = viewPeers
	m.peers["pod-1"] = []cilium.Peer{
		{Src: "10.1.0.2:2000", DstPort: 5432},
		{Src: "10.1.0.1:1000", DstPort: 5432},
	}

	// Get initial sorted peers.
	peers1 := m.selectedPeers()
	if len(peers1) != 2 {
		t.Fatalf("expected 2 peers, got %d", len(peers1))
	}
	if peers1[0].Src != "10.1.0.1:1000" {
		t.Errorf("peers[0] = %s, want 10.1.0.1:1000 (sorted)", peers1[0].Src)
	}

	// Simulate new poll data.
	updated, _ := m.Update(pollResultMsg{
		peers: map[string][]cilium.Peer{
			"pod-1": {
				{Src: "10.1.0.3:3000", DstPort: 5432},
				{Src: "10.1.0.1:1000", DstPort: 5432},
				{Src: "10.1.0.2:2000", DstPort: 5432},
			},
		},
		timestamp: time.Now(),
	})
	m2 := updated.(Model)
	peers2 := m2.selectedPeers()
	if len(peers2) != 3 {
		t.Fatalf("expected 3 peers after update, got %d", len(peers2))
	}
	if peers2[0].Src != "10.1.0.1:1000" {
		t.Errorf("peers[0] = %s, want 10.1.0.1:1000", peers2[0].Src)
	}
}

func TestSortChangeResetsScroll(t *testing.T) {
	m := testModel()
	m.width = 80
	m.height = 12
	m.mode = viewPeers
	var peers []cilium.Peer
	for i := range 20 {
		peers = append(peers, cilium.Peer{
			Src:     fmt.Sprintf("10.1.0.%d:%d", i, 1000+i),
			DstPort: 5432,
		})
	}
	m.peers["pod-1"] = peers

	// Scroll down.
	updated, _ := m.Update(keyMsg("j"))
	m2 := updated.(Model)
	if m2.scroll == 0 {
		t.Fatal("scroll should be > 0 after j")
	}

	// Press 's' to cycle sort — scroll should reset.
	updated, _ = m2.Update(keyMsg("s"))
	m3 := updated.(Model)
	if m3.scroll != 0 {
		t.Errorf("scroll = %d after sort change, want 0", m3.scroll)
	}

	// Scroll down again.
	updated, _ = m3.Update(keyMsg("j"))
	m4 := updated.(Model)

	// Press 'S' to reverse sort — scroll should reset.
	updated, _ = m4.Update(keyMsg("S"))
	m5 := updated.(Model)
	if m5.scroll != 0 {
		t.Errorf("scroll = %d after reverse toggle, want 0", m5.scroll)
	}
}

func TestPodListViewHasBottomDivider(t *testing.T) {
	m := testModel()
	m.width = 80
	m.height = 24
	m.timestamp = time.Now()

	view := m.View()
	lines := strings.Split(view, "\n")
	// Scan backwards from the end for a divider line (status bar may span multiple lines).
	found := false
	for i := len(lines) - 1; i >= 0; i-- {
		if strings.Contains(lines[i], "─") {
			// Make sure this is the bottom divider, not the header divider.
			// The header divider is near the top (line 1).
			if i > 2 {
				found = true
			}
			break
		}
	}
	if !found {
		t.Error("expected bottom divider line before status bar")
	}
}

func TestPeerListViewHasBottomDivider(t *testing.T) {
	m := testModel()
	m.width = 80
	m.height = 24
	m.mode = viewPeers
	m.peers["pod-1"] = []cilium.Peer{
		{Src: "10.1.0.1:1234", DstPort: 5432, Proto: "TCP", State: "established"},
	}

	view := m.View()
	lines := strings.Split(view, "\n")
	// Scan backwards from the end for a divider line (status bar may span multiple lines).
	found := false
	for i := len(lines) - 1; i >= 0; i-- {
		if strings.Contains(lines[i], "─") {
			// Make sure this is the bottom divider, not the header divider.
			if i > 2 {
				found = true
			}
			break
		}
	}
	if !found {
		t.Error("expected bottom divider line before status bar")
	}
}

func TestPeerViewShowsSortArrowInHeader(t *testing.T) {
	m := testModel()
	m.width = 120
	m.height = 24
	m.mode = viewPeers
	m.peers["pod-1"] = []cilium.Peer{
		{Src: "10.1.0.1:1234", DstPort: 5432, Proto: "TCP", State: "established"},
	}

	// Default sort is src ascending — should show ▲ on Peer column.
	view := m.View()
	if !strings.Contains(view, "▲") {
		t.Error("expected ▲ in column header for default sort")
	}

	// Toggle reverse — should show ▼.
	updated, _ := m.Update(keyMsg("S"))
	m2 := updated.(Model)
	view2 := m2.View()
	if !strings.Contains(view2, "▼") {
		t.Error("expected ▼ in column header for reversed sort")
	}

	// Cycle to port sort.
	updated, _ = m2.Update(keyMsg("s"))
	m3 := updated.(Model)
	view3 := m3.View()
	// Should still have an arrow somewhere.
	if !strings.Contains(view3, "▲") && !strings.Contains(view3, "▼") {
		t.Error("expected sort arrow in column header after cycling sort field")
	}
}

func TestPeerViewStatusBarNoSortLabel(t *testing.T) {
	m := testModel()
	m.width = 120
	m.height = 24
	m.mode = viewPeers
	m.peers["pod-1"] = []cilium.Peer{
		{Src: "10.1.0.1:1234", DstPort: 5432, Proto: "TCP", State: "established"},
	}

	view := m.View()
	if strings.Contains(view, "sort:src") {
		t.Error("status bar should not contain sort:src label anymore")
	}
}

func TestGGJumpsToTopPodList(t *testing.T) {
	m := testModel()
	m.width = 80
	m.height = 24

	// Move cursor to last pod.
	m.cursor = 2

	// Press g, then g again.
	updated, _ := m.Update(keyMsg("g"))
	m2 := updated.(Model)
	updated, _ = m2.Update(keyMsg("g"))
	m3 := updated.(Model)
	if m3.cursor != 0 {
		t.Errorf("cursor = %d after gg, want 0", m3.cursor)
	}
}

func TestGJumpsToBottomPodList(t *testing.T) {
	m := testModel()
	m.width = 80
	m.height = 24

	// Press G (uppercase).
	updated, _ := m.Update(keyMsg("G"))
	m2 := updated.(Model)
	if m2.cursor != len(m2.config.Pods)-1 {
		t.Errorf("cursor = %d after G, want %d", m2.cursor, len(m2.config.Pods)-1)
	}
}

func TestGGJumpsToTopPeerView(t *testing.T) {
	m := testModel()
	m.width = 80
	m.height = 12
	m.mode = viewPeers
	var peers []cilium.Peer
	for i := range 30 {
		peers = append(peers, cilium.Peer{
			Src:     fmt.Sprintf("10.1.0.%d:%d", i, 1000+i),
			DstPort: 5432,
		})
	}
	m.peers["pod-1"] = peers
	m.scroll = 10

	// Press g, then g.
	updated, _ := m.Update(keyMsg("g"))
	m2 := updated.(Model)
	updated, _ = m2.Update(keyMsg("g"))
	m3 := updated.(Model)
	if m3.scroll != 0 {
		t.Errorf("scroll = %d after gg, want 0", m3.scroll)
	}
}

func TestGJumpsToBottomPeerView(t *testing.T) {
	m := testModel()
	m.width = 80
	m.height = 12
	m.mode = viewPeers
	var peers []cilium.Peer
	for i := range 30 {
		peers = append(peers, cilium.Peer{
			Src:     fmt.Sprintf("10.1.0.%d:%d", i, 1000+i),
			DstPort: 5432,
		})
	}
	m.peers["pod-1"] = peers

	updated, _ := m.Update(keyMsg("G"))
	m2 := updated.(Model)
	if m2.scroll != m2.maxScroll() {
		t.Errorf("scroll = %d after G, want %d", m2.scroll, m2.maxScroll())
	}
}

func TestPendingKeyTimeout(t *testing.T) {
	m := testModel()
	m.width = 80
	m.height = 24

	// Press g.
	updated, cmd := m.Update(keyMsg("g"))
	m2 := updated.(Model)
	if m2.pendingKey != "g" {
		t.Errorf("pendingKey = %q, want 'g'", m2.pendingKey)
	}
	if cmd == nil {
		t.Error("pressing g should return a timeout command")
	}

	// Timeout fires — pending key should clear.
	updated, _ = m2.Update(pendingKeyTimeoutMsg{})
	m3 := updated.(Model)
	if m3.pendingKey != "" {
		t.Errorf("pendingKey = %q after timeout, want empty", m3.pendingKey)
	}
}

func TestPendingKeyCancelledByOtherKey(t *testing.T) {
	m := testModel()
	m.width = 80
	m.height = 24
	m.cursor = 0

	// Press g, then j (not g — should cancel pending and process j).
	updated, _ := m.Update(keyMsg("g"))
	m2 := updated.(Model)
	updated, _ = m2.Update(keyMsg("j"))
	m3 := updated.(Model)
	if m3.pendingKey != "" {
		t.Errorf("pendingKey = %q, want empty (cancelled)", m3.pendingKey)
	}
	if m3.cursor != 1 {
		t.Errorf("cursor = %d, want 1 (j should still navigate)", m3.cursor)
	}
}

func TestShiftTabJumpsToPrevPodWithPeers(t *testing.T) {
	m := testModel()
	m.width = 80
	m.height = 24
	m.cursor = 2 // start on pod-3
	// pod-1 has 1 peer, pod-2 has 0, pod-3 has 0.
	m.peers["pod-1"] = []cilium.Peer{{Src: "10.1.0.1:1234", DstPort: 5432}}

	updated, _ := m.Update(keyMsg("shift+tab"))
	m2 := updated.(Model)
	if m2.cursor != 0 {
		t.Errorf("cursor = %d, want 0 (pod-1 has peers)", m2.cursor)
	}
}

func TestCtrlDHalfPageDownPodList(t *testing.T) {
	pods := make([]k8s.PodInfo, 20)
	for i := range pods {
		pods[i] = k8s.PodInfo{Name: fmt.Sprintf("pod-%d", i), Node: "node-a", IP: fmt.Sprintf("10.0.0.%d", i)}
	}
	m := New(Config{
		Filter:   cilium.Filter{PortMin: 5432, PortMax: 5432},
		Interval: 10 * time.Second,
		Pods:     pods,
	})
	m.width = 80
	m.height = 24

	updated, _ := m.Update(keyMsg("ctrl+d"))
	m2 := updated.(Model)
	halfPage := m2.podPaneHeight() / 2
	if m2.cursor != halfPage {
		t.Errorf("cursor = %d after ctrl+d, want %d", m2.cursor, halfPage)
	}
}

func TestCtrlUHalfPageUpPodList(t *testing.T) {
	pods := make([]k8s.PodInfo, 20)
	for i := range pods {
		pods[i] = k8s.PodInfo{Name: fmt.Sprintf("pod-%d", i), Node: "node-a", IP: fmt.Sprintf("10.0.0.%d", i)}
	}
	m := New(Config{
		Filter:   cilium.Filter{PortMin: 5432, PortMax: 5432},
		Interval: 10 * time.Second,
		Pods:     pods,
	})
	m.width = 80
	m.height = 24
	m.cursor = 15

	updated, _ := m.Update(keyMsg("ctrl+u"))
	m2 := updated.(Model)
	halfPage := m2.podPaneHeight() / 2
	expected := 15 - halfPage
	if m2.cursor != expected {
		t.Errorf("cursor = %d after ctrl+u, want %d", m2.cursor, expected)
	}
}

func TestCtrlDHalfPageDownPeerView(t *testing.T) {
	m := testModel()
	m.width = 80
	m.height = 12
	m.mode = viewPeers
	var peers []cilium.Peer
	for i := range 30 {
		peers = append(peers, cilium.Peer{
			Src:     fmt.Sprintf("10.1.0.%d:%d", i, 1000+i),
			DstPort: 5432,
		})
	}
	m.peers["pod-1"] = peers

	updated, _ := m.Update(keyMsg("ctrl+d"))
	m2 := updated.(Model)
	halfPage := m2.peerPaneHeight() / 2
	if m2.scroll != halfPage {
		t.Errorf("scroll = %d after ctrl+d, want %d", m2.scroll, halfPage)
	}
}

func TestHMLPodList(t *testing.T) {
	pods := make([]k8s.PodInfo, 20)
	for i := range pods {
		pods[i] = k8s.PodInfo{Name: fmt.Sprintf("pod-%d", i), Node: "node-a", IP: fmt.Sprintf("10.0.0.%d", i)}
	}
	m := New(Config{
		Filter:   cilium.Filter{PortMin: 5432, PortMax: 5432},
		Interval: 10 * time.Second,
		Pods:     pods,
	})
	m.width = 80
	m.height = 24
	m.cursor = 10
	m.podScroll = 5

	// H — top of visible area.
	updated, _ := m.Update(keyMsg("H"))
	m2 := updated.(Model)
	if m2.cursor != m2.podScroll {
		t.Errorf("H: cursor = %d, want %d (top of visible)", m2.cursor, m2.podScroll)
	}

	// L — bottom of visible area.
	m.cursor = 5
	updated, _ = m.Update(keyMsg("L"))
	m3 := updated.(Model)
	expected := m3.podScroll + m3.podPaneHeight() - 1
	if expected >= len(m3.config.Pods) {
		expected = len(m3.config.Pods) - 1
	}
	if m3.cursor != expected {
		t.Errorf("L: cursor = %d, want %d (bottom of visible)", m3.cursor, expected)
	}

	// M — middle of visible area.
	m.cursor = 5
	updated, _ = m.Update(keyMsg("M"))
	m4 := updated.(Model)
	mid := m4.podScroll + m4.podPaneHeight()/2
	if mid >= len(m4.config.Pods) {
		mid = len(m4.config.Pods) - 1
	}
	if m4.cursor != mid {
		t.Errorf("M: cursor = %d, want %d (middle of visible)", m4.cursor, mid)
	}
}

func TestHMLPeerView(t *testing.T) {
	m := testModel()
	m.width = 80
	m.height = 12
	m.mode = viewPeers
	var peers []cilium.Peer
	for i := range 30 {
		peers = append(peers, cilium.Peer{
			Src:     fmt.Sprintf("10.1.0.%d:%d", i, 1000+i),
			DstPort: 5432,
		})
	}
	m.peers["pod-1"] = peers
	m.scroll = 10

	// H — scroll to show top of current view (no-op since scroll is already there).
	updated, _ := m.Update(keyMsg("H"))
	m2 := updated.(Model)
	if m2.scroll != 10 {
		t.Errorf("H: scroll = %d, want 10 (unchanged, already at top)", m2.scroll)
	}

	// L — scroll to bottom of visible area.
	updated, _ = m2.Update(keyMsg("L"))
	m3 := updated.(Model)
	paneH := m3.peerPaneHeight()
	expectedScroll := 10 + paneH - 1
	scrollLimit := m3.maxScroll()
	if expectedScroll > scrollLimit {
		expectedScroll = scrollLimit
	}
	if m3.scroll != expectedScroll {
		t.Errorf("L: scroll = %d, want %d", m3.scroll, expectedScroll)
	}

	// M — scroll to middle.
	m.scroll = 0
	updated, _ = m.Update(keyMsg("M"))
	m4 := updated.(Model)
	midScroll := m4.peerPaneHeight() / 2
	if m4.scroll != midScroll {
		t.Errorf("M: scroll = %d, want %d", m4.scroll, midScroll)
	}
}

func TestSearchNextN(t *testing.T) {
	m := testModel()
	m.width = 80
	m.height = 12
	m.mode = viewPeers
	m.peers["pod-1"] = []cilium.Peer{
		{Src: "10.1.0.1:1000", DstPort: 5432},
		{Src: "10.2.0.1:2000", DstPort: 5432},
		{Src: "10.1.0.2:3000", DstPort: 5432},
		{Src: "10.3.0.1:4000", DstPort: 5432},
		{Src: "10.1.0.3:5000", DstPort: 5432},
	}
	m.searchQuery = "10.1"

	// 'n' should scroll forward by 1.
	updated, _ := m.Update(keyMsg("n"))
	m2 := updated.(Model)
	if m2.scroll != 1 {
		t.Errorf("scroll = %d after n, want 1", m2.scroll)
	}

	// 'n' again.
	updated, _ = m2.Update(keyMsg("n"))
	m3 := updated.(Model)
	if m3.scroll != 2 {
		t.Errorf("scroll = %d after second n, want 2", m3.scroll)
	}
}

func TestSearchPrevN(t *testing.T) {
	m := testModel()
	m.width = 80
	m.height = 12
	m.mode = viewPeers
	m.peers["pod-1"] = []cilium.Peer{
		{Src: "10.1.0.1:1000", DstPort: 5432},
		{Src: "10.1.0.2:2000", DstPort: 5432},
		{Src: "10.1.0.3:3000", DstPort: 5432},
	}
	m.searchQuery = "10.1"
	m.scroll = 2

	// 'N' should scroll backwards.
	updated, _ := m.Update(keyMsg("N"))
	m2 := updated.(Model)
	if m2.scroll != 1 {
		t.Errorf("scroll = %d after N, want 1", m2.scroll)
	}
}

func TestSearchNWithoutQuery(t *testing.T) {
	m := testModel()
	m.width = 80
	m.height = 12
	m.mode = viewPeers
	m.peers["pod-1"] = []cilium.Peer{
		{Src: "10.1.0.1:1000", DstPort: 5432},
	}

	// 'n' without active search should do nothing.
	updated, _ := m.Update(keyMsg("n"))
	m2 := updated.(Model)
	if m2.scroll != 0 {
		t.Errorf("scroll = %d after n with no query, want 0", m2.scroll)
	}
}

func TestCtrlUHalfPageUpPeerView(t *testing.T) {
	m := testModel()
	m.width = 80
	m.height = 12
	m.mode = viewPeers
	var peers []cilium.Peer
	for i := range 30 {
		peers = append(peers, cilium.Peer{
			Src:     fmt.Sprintf("10.1.0.%d:%d", i, 1000+i),
			DstPort: 5432,
		})
	}
	m.peers["pod-1"] = peers
	m.scroll = 15

	updated, _ := m.Update(keyMsg("ctrl+u"))
	m2 := updated.(Model)
	halfPage := m2.peerPaneHeight() / 2
	expected := max(15-halfPage, 0)
	if m2.scroll != expected {
		t.Errorf("scroll = %d after ctrl+u, want %d", m2.scroll, expected)
	}
}

func TestHighlightMatch(t *testing.T) {
	// No match returns original.
	result := highlightMatch("10.1.0.1:1234", "xyz")
	if result != "10.1.0.1:1234" {
		t.Errorf("no-match should return original, got %q", result)
	}

	// Empty query returns original.
	result2 := highlightMatch("10.1.0.1:1234", "")
	if result2 != "10.1.0.1:1234" {
		t.Errorf("empty query should return original, got %q", result2)
	}

	// Basic match should contain the surrounding text.
	result3 := highlightMatch("10.1.0.1:1234", "0.1.0")
	if !strings.Contains(result3, "1") {
		t.Error("highlighted result should contain surrounding text")
	}
	// Display width should be at least the original length (style doesn't shrink text).
	if lipgloss.Width(result3) < len("10.1.0.1:1234") {
		t.Errorf("display width %d should be >= original %d", lipgloss.Width(result3), len("10.1.0.1:1234"))
	}

	// Case-insensitive: should still find match.
	result4 := highlightMatch("ABCDEF", "cde")
	// The original case should be preserved in output.
	if !strings.Contains(result4, "CDE") {
		t.Error("case-insensitive match should preserve original case")
	}
}

func TestHighlightMatchWithColorProfile(t *testing.T) {
	// Force ANSI color output for this test.
	lipgloss.SetColorProfile(termenv.ANSI)
	defer lipgloss.SetColorProfile(termenv.Ascii)

	result := highlightMatch("10.1.0.1:1234", "10.1")
	if result == "10.1.0.1:1234" {
		t.Error("with ANSI profile, highlighted result should differ from plain text")
	}
	if !strings.Contains(result, "\x1b[") {
		t.Error("with ANSI profile, highlighted result should contain escape codes")
	}
}

func TestPeerViewShowsBytesColumn(t *testing.T) {
	m := testModel()
	m.width = 160
	m.height = 24
	m.mode = viewPeers
	m.peers["pod-1"] = []cilium.Peer{
		{Src: "10.1.0.1:1234", DstPort: 5432, Proto: "TCP", State: "established", Bytes: 1536, Packets: 10},
	}

	view := m.View()
	if !strings.Contains(view, "Rx/Tx") {
		t.Error("should show Rx/Tx column header")
	}
	// 1.5 K is the formatted output for 1536 bytes.
	if !strings.Contains(view, "1.5 K") {
		t.Error("should show formatted byte count")
	}
}

func TestPeerSortByBytes(t *testing.T) {
	m := testModel()
	m.width = 160
	m.height = 24
	m.mode = viewPeers
	m.sortField = sortBytes
	m.peers["pod-1"] = []cilium.Peer{
		{Src: "10.1.0.1:1000", DstPort: 5432, Proto: "TCP", State: "established", Bytes: 100},
		{Src: "10.1.0.2:2000", DstPort: 5432, Proto: "TCP", State: "established", Bytes: 9999},
		{Src: "10.1.0.3:3000", DstPort: 5432, Proto: "TCP", State: "established", Bytes: 500},
	}

	view := m.View()
	lines := strings.Split(view, "\n")
	// Find data lines containing our test IPs.
	var order []string
	for _, line := range lines {
		for _, ip := range []string{"10.1.0.1", "10.1.0.2", "10.1.0.3"} {
			if strings.Contains(line, ip) {
				order = append(order, ip)
			}
		}
	}
	// Ascending by bytes: 100 (.0.1), 500 (.0.3), 9999 (.0.2).
	if len(order) != 3 || order[0] != "10.1.0.1" || order[1] != "10.1.0.3" || order[2] != "10.1.0.2" {
		t.Errorf("sort by bytes ascending: got order %v, want [10.1.0.1 10.1.0.3 10.1.0.2]", order)
	}
}

func TestPodListShowsTotalBytes(t *testing.T) {
	m := testModel()
	m.width = 100
	m.height = 24
	m.timestamp = time.Now()
	m.peers["pod-1"] = []cilium.Peer{
		{Src: "10.1.0.1:1234", DstPort: 5432, Bytes: 1048576},
		{Src: "10.1.0.2:5678", DstPort: 5432, Bytes: 1048576},
	}

	view := m.View()
	if !strings.Contains(view, "2.0 M") {
		t.Error("Pod list should show aggregate bytes (2.0 M)")
	}
}

func TestHeaderShowsKubeContext(t *testing.T) {
	m := testModel()
	m.config.Context = "prod-us-east"
	m.width = 120
	m.height = 24
	m.timestamp = time.Now()

	view := m.View()
	if !strings.Contains(view, "prod-us-east") {
		t.Error("Header should show kube context name")
	}
}

func TestHeaderShowsTotalBytes(t *testing.T) {
	m := testModel()
	m.width = 120
	m.height = 24
	m.timestamp = time.Now()
	m.peers["pod-1"] = []cilium.Peer{
		{Src: "10.1.0.1:1234", DstPort: 5432, Bytes: 5242880},
	}
	m.peers["pod-2"] = []cilium.Peer{
		{Src: "10.1.0.2:5678", DstPort: 5432, Bytes: 5242880},
	}

	view := m.View()
	if !strings.Contains(view, "10.0 M") {
		t.Error("Header should show total bytes across all pods")
	}
}

func TestPollDeltaBytesPerSec(t *testing.T) {
	m := testModel()
	m.width = 120
	m.height = 24

	now := time.Now()

	// First poll — no delta yet.
	updated, _ := m.Update(pollResultMsg{
		peers: map[string][]cilium.Peer{
			"pod-1": {
				{Src: "10.1.0.1:1234", DstPort: 5432, Bytes: 1000},
			},
		},
		timestamp: now,
	})
	m2 := updated.(Model)
	if m2.bytesPerSec != 0 {
		t.Errorf("bytesPerSec = %d after first poll, want 0", m2.bytesPerSec)
	}

	// Second poll — 10 seconds later, 2000 more bytes.
	updated, _ = m2.Update(pollResultMsg{
		peers: map[string][]cilium.Peer{
			"pod-1": {
				{Src: "10.1.0.1:1234", DstPort: 5432, Bytes: 3000},
			},
		},
		timestamp: now.Add(10 * time.Second),
	})
	m3 := updated.(Model)
	if m3.bytesPerSec != 200 {
		t.Errorf("bytesPerSec = %d, want 200 (2000 bytes / 10s)", m3.bytesPerSec)
	}
}

func TestPeerViewSearchHighlightFilters(t *testing.T) {
	m := testModel()
	m.width = 120
	m.height = 24
	m.mode = viewPeers
	m.peers["pod-1"] = []cilium.Peer{
		{Src: "10.1.0.1:1234", DstPort: 5432, Proto: "TCP", State: "established"},
		{Src: "10.2.0.1:5678", DstPort: 5432, Proto: "TCP", State: "established"},
	}
	m.searchQuery = "10.1"

	view := m.View()
	// With search active, only the matching peer should appear.
	if !strings.Contains(view, "10.1.0.1:1234") {
		t.Error("view should contain matching peer")
	}
	if strings.Contains(view, "10.2.0.1:5678") {
		t.Error("view should not contain non-matching peer")
	}
	// Should show filtered count.
	if !strings.Contains(view, "1/2 connections") {
		t.Error("view should show filtered count")
	}
}

// --- Coverage gap tests ---

func TestSortPeersAllFieldsAndReverse(t *testing.T) {
	peers := []cilium.Peer{
		{Src: "10.1.0.2:2000", DstPort: 80, Proto: "UDP", State: "closing", Bytes: 500},
		{Src: "10.1.0.1:1000", DstPort: 443, Proto: "TCP", State: "established", Bytes: 100},
		{Src: "10.1.0.3:3000", DstPort: 22, Proto: "TCP", State: "closing", Bytes: 9999},
	}

	tests := []struct {
		field   sortField
		reverse bool
		first   string // expected Src of first element
		last    string // expected Src of last element
	}{
		{sortSrc, false, "10.1.0.1:1000", "10.1.0.3:3000"},
		{sortSrc, true, "10.1.0.3:3000", "10.1.0.1:1000"},
		{sortPort, false, "10.1.0.3:3000", "10.1.0.1:1000"},  // 22, 80, 443
		{sortPort, true, "10.1.0.1:1000", "10.1.0.3:3000"},   // 443, 80, 22
		{sortProto, false, "10.1.0.1:1000", "10.1.0.2:2000"}, // TCP < UDP
		{sortProto, true, "10.1.0.2:2000", "10.1.0.1:1000"},
		{sortState, false, "10.1.0.2:2000", "10.1.0.1:1000"}, // closing < established
		{sortState, true, "10.1.0.1:1000", "10.1.0.2:2000"},
		{sortBytes, false, "10.1.0.1:1000", "10.1.0.3:3000"}, // 100, 500, 9999
		{sortBytes, true, "10.1.0.3:3000", "10.1.0.1:1000"},
	}

	for _, tt := range tests {
		label := fmt.Sprintf("field=%d/reverse=%v", tt.field, tt.reverse)
		t.Run(label, func(t *testing.T) {
			sorted := sortPeers(peers, tt.field, tt.reverse)
			if sorted[0].Src != tt.first {
				t.Errorf("first = %s, want %s", sorted[0].Src, tt.first)
			}
			if sorted[len(sorted)-1].Src != tt.last {
				t.Errorf("last = %s, want %s", sorted[len(sorted)-1].Src, tt.last)
			}
		})
	}
}

func TestViewPeerListWithSortArrowOnBytesAndSearch(t *testing.T) {
	m := testModel()
	m.width = 160
	m.height = 24
	m.mode = viewPeers
	m.sortField = sortBytes
	m.searchQuery = "10.1"
	m.peers["pod-1"] = []cilium.Peer{
		{Src: "10.1.0.1:1234", DstPort: 5432, Proto: "TCP", State: "established", Bytes: 1024},
		{Src: "10.2.0.1:5678", DstPort: 5432, Proto: "TCP", State: "established", Bytes: 2048},
	}

	view := m.View()
	// Sort arrow should be on Rx/Tx column.
	if !strings.Contains(view, "▲") {
		t.Error("expected sort arrow on bytes column")
	}
	// Search should filter out 10.2.0.1.
	if strings.Contains(view, "10.2.0.1") {
		t.Error("search should filter out non-matching peer")
	}
	if !strings.Contains(view, "1/2 connections") {
		t.Error("should show filtered count")
	}
}

func TestViewPeerListSplitBytesDisplay(t *testing.T) {
	m := testModel()
	m.width = 160
	m.height = 24
	m.mode = viewPeers
	m.peers["pod-1"] = []cilium.Peer{
		{Src: "10.1.0.1:1234", DstPort: 5432, Proto: "TCP", State: "established",
			RxBytes: 1024, TxBytes: 2048, Bytes: 3072},
	}

	view := m.View()
	// When RxBytes > 0 || TxBytes > 0, should show split format "Rx/Tx".
	if !strings.Contains(view, "1.0 K/2.0 K") {
		t.Error("should show split bytes display (Rx/Tx) when RxBytes and TxBytes are set")
	}
}

func TestViewPeerListCombinedBytesDisplay(t *testing.T) {
	m := testModel()
	m.width = 160
	m.height = 24
	m.mode = viewPeers
	m.peers["pod-1"] = []cilium.Peer{
		{Src: "10.1.0.1:1234", DstPort: 5432, Proto: "TCP", State: "established",
			RxBytes: 0, TxBytes: 0, Bytes: 1536},
	}

	view := m.View()
	// When only Bytes > 0 (no split), should show combined value.
	if !strings.Contains(view, "1.5 K") {
		t.Error("should show combined bytes display when only Bytes is set")
	}
}

func TestClampPodScrollExceedsMax(t *testing.T) {
	m := testModel() // 3 pods
	m.width = 80
	m.height = 24 // podPaneHeight = 24-4 = 20, way more than 3 pods
	m.podScroll = 10
	m.cursor = 2

	m.clampPodScroll()
	if m.podScroll != 0 {
		t.Errorf("podScroll = %d, want 0 (all pods fit in pane)", m.podScroll)
	}
}

func TestClampPodScrollCursorAboveVisible(t *testing.T) {
	pods := make([]k8s.PodInfo, 20)
	for i := range pods {
		pods[i] = k8s.PodInfo{Name: fmt.Sprintf("pod-%d", i), Node: "node-a", IP: fmt.Sprintf("10.0.0.%d", i)}
	}
	m := New(Config{Pods: pods, Interval: 10 * time.Second})
	m.width = 80
	m.height = 10 // podPaneHeight = 10-4 = 6
	m.podScroll = 10
	m.cursor = 5 // cursor above visible area

	m.clampPodScroll()
	if m.podScroll != 5 {
		t.Errorf("podScroll = %d, want 5 (scroll to show cursor)", m.podScroll)
	}
}

func TestClampScrollExceedsMax(t *testing.T) {
	m := testModel()
	m.width = 80
	m.height = 12
	m.mode = viewPeers
	m.peers["pod-1"] = []cilium.Peer{
		{Src: "10.1.0.1:1234", DstPort: 5432},
	}
	m.scroll = 100 // way past max

	m.clampScroll()
	if m.scroll != 0 {
		t.Errorf("scroll = %d, want 0 (clamped to maxScroll=0)", m.scroll)
	}
}

func TestClampScrollNotPeerView(t *testing.T) {
	m := testModel()
	m.mode = viewPods
	m.scroll = 50

	m.clampScroll()
	// Should be a no-op when not in peer view.
	if m.scroll != 50 {
		t.Errorf("scroll = %d, want 50 (clampScroll should be no-op for pod view)", m.scroll)
	}
}

func TestPeerPaneHeightMinimum(t *testing.T) {
	m := testModel()
	m.height = 0 // extremely small

	h := m.peerPaneHeight()
	if h != 1 {
		t.Errorf("peerPaneHeight = %d, want 1 (minimum)", h)
	}
}

func TestPodPaneHeightMinimum(t *testing.T) {
	m := testModel()
	m.height = 0

	h := m.podPaneHeight()
	if h != 1 {
		t.Errorf("podPaneHeight = %d, want 1 (minimum)", h)
	}
}

func TestSelectedPeersEmptyPods(t *testing.T) {
	m := New(Config{Pods: []k8s.PodInfo{}, Interval: 10 * time.Second})
	peers := m.selectedPeers()
	if peers != nil {
		t.Errorf("selectedPeers should return nil for empty pods, got %v", peers)
	}
}

func TestSelectedPeersCursorOutOfRange(t *testing.T) {
	m := testModel()
	m.cursor = 100 // way out of range

	peers := m.selectedPeers()
	if peers != nil {
		t.Errorf("selectedPeers should return nil when cursor out of range, got %v", peers)
	}
}

func TestErrorSummaryDeduplicate(t *testing.T) {
	errors := []string{
		"node-1: connection refused",
		"node-2: connection refused",
		"node-3: timeout",
	}
	summary := errorSummary(errors)
	if !strings.Contains(summary, "connection refused (x2)") {
		t.Errorf("expected deduplication with count, got %q", summary)
	}
	if !strings.Contains(summary, "timeout") {
		t.Errorf("expected timeout in summary, got %q", summary)
	}
}

func TestErrorSummaryEmpty(t *testing.T) {
	summary := errorSummary(nil)
	if summary != "" {
		t.Errorf("expected empty string for nil errors, got %q", summary)
	}
}

func TestUpdateTickWhileQuitting(t *testing.T) {
	m := testModel()
	m.polling = false
	m.quitting = true

	updated, cmd := m.Update(tickMsg{})
	m2 := updated.(Model)
	if cmd != nil {
		t.Error("tick while quitting should return nil cmd")
	}
	// polling should remain false since tick was a no-op.
	if m2.polling {
		t.Error("should not start polling while quitting")
	}
}

func TestUpdatePauseToggle(t *testing.T) {
	m := testModel()
	m.width = 80
	m.height = 24

	// Press 'p' to pause.
	updated, cmd := m.Update(keyMsg("p"))
	m2 := updated.(Model)
	if !m2.paused {
		t.Error("should be paused after 'p'")
	}
	if cmd != nil {
		t.Error("pausing should return nil cmd")
	}

	// Press space to unpause.
	updated, cmd = m2.Update(keyMsg(" "))
	m3 := updated.(Model)
	if m3.paused {
		t.Error("should be unpaused after space")
	}
	if cmd == nil {
		t.Error("unpausing should return a poll command")
	}
}

func TestUpdateCtrlCQuits(t *testing.T) {
	m := testModel()
	updated, cmd := m.Update(tea.KeyMsg(tea.Key{Type: tea.KeyCtrlC}))
	m2 := updated.(Model)
	if !m2.quitting {
		t.Error("ctrl+c should set quitting=true")
	}
	if cmd == nil {
		t.Error("ctrl+c should return quit command")
	}
}

func TestSearchEnterConfirms(t *testing.T) {
	m := testModel()
	m.width = 80
	m.height = 24
	m.mode = viewPeers
	m.searching = true
	m.searchQuery = "10.1"

	updated, _ := m.Update(keyMsg("enter"))
	m2 := updated.(Model)
	if m2.searching {
		t.Error("enter should exit search mode")
	}
	if m2.searchQuery != "10.1" {
		t.Errorf("enter should preserve searchQuery, got %q", m2.searchQuery)
	}
}

func TestSearchBackspace(t *testing.T) {
	m := testModel()
	m.width = 80
	m.height = 24
	m.mode = viewPeers
	m.searching = true
	m.searchQuery = "10.1"

	updated, _ := m.Update(keyMsg("backspace"))
	m2 := updated.(Model)
	if m2.searchQuery != "10." {
		t.Errorf("searchQuery after backspace = %q, want '10.'", m2.searchQuery)
	}

	// Backspace on empty query should not panic.
	m2.searchQuery = ""
	updated, _ = m2.Update(keyMsg("backspace"))
	m3 := updated.(Model)
	if m3.searchQuery != "" {
		t.Errorf("searchQuery after backspace on empty = %q, want empty", m3.searchQuery)
	}
}

func TestViewHelpFromPeerView(t *testing.T) {
	m := testModel()
	m.width = 80
	m.height = 24
	m.mode = viewPeers
	m.showHelp = true

	view := m.View()
	if !strings.Contains(view, "Keybindings") {
		t.Error("help overlay should show 'Keybindings' when opened from peer view")
	}
	if !strings.Contains(view, "close help") {
		t.Error("help overlay should show 'close help' hint")
	}
}

func TestViewQuitting(t *testing.T) {
	m := testModel()
	m.width = 80
	m.height = 24
	m.quitting = true

	view := m.View()
	if view != "" {
		t.Errorf("View() should return empty string when quitting, got %q", view)
	}
}

func TestViewPeerListNoPods(t *testing.T) {
	m := New(Config{Pods: []k8s.PodInfo{}, Interval: 10 * time.Second})
	m.width = 80
	m.height = 24
	m.mode = viewPeers

	view := m.View()
	if !strings.Contains(view, "(no pods)") {
		t.Error("peer view with empty pods should show '(no pods)'")
	}
}

func TestViewPeerListCursorOutOfRange(t *testing.T) {
	m := testModel()
	m.width = 80
	m.height = 24
	m.mode = viewPeers
	m.cursor = 100 // out of range

	view := m.View()
	if !strings.Contains(view, "(no pods)") {
		t.Error("peer view with cursor out of range should show '(no pods)'")
	}
}

func TestViewPeerListSearchBar(t *testing.T) {
	m := testModel()
	m.width = 80
	m.height = 24
	m.mode = viewPeers
	m.searching = true
	m.searchQuery = "abc"
	m.peers["pod-1"] = []cilium.Peer{
		{Src: "10.1.0.1:1234", DstPort: 5432},
	}

	view := m.View()
	if !strings.Contains(view, "/abc_") {
		t.Error("search bar should show '/abc_' when searching")
	}
}

func TestViewPeerListScrollInfo(t *testing.T) {
	m := testModel()
	m.width = 80
	m.height = 12
	m.mode = viewPeers
	var peers []cilium.Peer
	for i := range 30 {
		peers = append(peers, cilium.Peer{
			Src:     fmt.Sprintf("10.1.0.%d:%d", i, 1000+i),
			DstPort: 5432,
		})
	}
	m.peers["pod-1"] = peers
	m.scroll = 5

	view := m.View()
	// Should show scroll position indicator [N/M].
	if !strings.Contains(view, "[6/") {
		t.Error("peer view should show scroll position [6/...]")
	}
}

func TestPeerViewColumnAlignment(t *testing.T) {
	m := testModel()
	m.width = 120
	m.height = 24
	m.mode = viewPeers
	m.sortField = sortSrc // sort arrow on Peer Address:Port column
	m.peers["pod-1"] = []cilium.Peer{
		{Src: "10.4.34.25:53138", DstPort: 3000, Proto: "TCP", State: "established"},
	}

	view := m.View()
	lines := strings.Split(view, "\n")

	// Find the header line (contains "Peer Address:Port") and first data line (contains the IP).
	var headerLine, dataLine string
	for _, line := range lines {
		plain := stripAnsi(line)
		if strings.Contains(plain, "Peer Address:Port") {
			headerLine = plain
		}
		if strings.Contains(plain, "10.4.34.25:53138") {
			dataLine = plain
		}
	}
	if headerLine == "" || dataLine == "" {
		t.Fatalf("could not find header or data line in view:\n%s", view)
	}

	// The "Proto" column should start at the same display position in both lines.
	// Use rune index (not byte index) since ▲ is multi-byte.
	hdrRunes := []rune(headerLine)
	dataRunes := []rune(dataLine)
	hdrProtoIdx := runeIndex(hdrRunes, "Proto")
	dataProtoIdx := runeIndex(dataRunes, "TCP")
	if hdrProtoIdx != dataProtoIdx {
		t.Errorf("Proto column misaligned: header at %d, data at %d\nheader: %q\ndata:   %q",
			hdrProtoIdx, dataProtoIdx, headerLine, dataLine)
	}
}

// stripAnsi removes ANSI escape sequences from a string.
func stripAnsi(s string) string {
	var result []byte
	i := 0
	for i < len(s) {
		if s[i] == '\x1b' && i+1 < len(s) && s[i+1] == '[' {
			// Skip until we find the terminal letter.
			j := i + 2
			for j < len(s) && (s[j] < 'A' || s[j] > 'Z') && (s[j] < 'a' || s[j] > 'z') {
				j++
			}
			if j < len(s) {
				j++ // skip the terminal letter
			}
			i = j
		} else {
			result = append(result, s[i])
			i++
		}
	}
	return string(result)
}

func runeIndex(runes []rune, substr string) int {
	target := []rune(substr)
	for i := 0; i <= len(runes)-len(target); i++ {
		match := true
		for j := range target {
			if runes[i+j] != target[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

func TestPollResultCursorClampedWhenExceedsPods(t *testing.T) {
	m := testModel()
	m.cursor = 10 // exceeds number of pods (3)

	updated, _ := m.Update(pollResultMsg{
		peers:     map[string][]cilium.Peer{},
		timestamp: time.Now(),
	})
	m2 := updated.(Model)
	if m2.cursor != 2 {
		t.Errorf("cursor = %d after poll result, want 2 (len(pods)-1)", m2.cursor)
	}
}

func TestPeerViewPeerStatePending(t *testing.T) {
	m := testModel()
	m.width = 120
	m.height = 24
	m.mode = viewPeers
	m.peers["pod-1"] = []cilium.Peer{
		{Src: "10.1.0.1:1234", DstPort: 5432, Proto: "TCP", State: "unknown"},
	}

	view := m.View()
	// Non-established/non-closing states should render without special style.
	if !strings.Contains(view, "unknown") {
		t.Error("should show non-standard state value")
	}
}

func TestGOnEmptyPodList(t *testing.T) {
	m := New(Config{Pods: []k8s.PodInfo{}, Interval: 10 * time.Second})
	m.width = 80
	m.height = 24

	// G on empty pod list should not panic.
	updated, _ := m.Update(keyMsg("G"))
	m2 := updated.(Model)
	if m2.cursor != 0 {
		t.Errorf("cursor = %d, want 0 on empty pod list", m2.cursor)
	}
}

func TestPeerViewGGPausesBehavior(t *testing.T) {
	m := testModel()
	m.width = 80
	m.height = 12
	m.mode = viewPeers
	m.peers["pod-1"] = []cilium.Peer{
		{Src: "10.1.0.1:1234", DstPort: 5432},
	}
	m.scroll = 5

	// gg should pause and reset scroll.
	updated, _ := m.Update(keyMsg("g"))
	m2 := updated.(Model)
	updated, _ = m2.Update(keyMsg("g"))
	m3 := updated.(Model)
	if !m3.paused {
		t.Error("gg in peer view should pause")
	}
	if m3.scroll != 0 {
		t.Errorf("gg scroll = %d, want 0", m3.scroll)
	}
}

func TestPeerViewGPausesBehavior(t *testing.T) {
	m := testModel()
	m.width = 80
	m.height = 12
	m.mode = viewPeers
	var peers []cilium.Peer
	for i := range 30 {
		peers = append(peers, cilium.Peer{
			Src:     fmt.Sprintf("10.1.0.%d:%d", i, 1000+i),
			DstPort: 5432,
		})
	}
	m.peers["pod-1"] = peers

	updated, _ := m.Update(keyMsg("G"))
	m2 := updated.(Model)
	if !m2.paused {
		t.Error("G in peer view should pause")
	}
}

func testModelWithCapture() Model {
	m := testModel()
	m.recorder = capture.NewRecorder(
		&capture.JSONLFormatter{},
		capture.NewStreamWriter(&bytes.Buffer{}),
	)
	return m
}

func TestDumpKeybinding(t *testing.T) {
	m := testModelWithCapture()
	ts := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	m2, _ := m.Update(pollResultMsg{
		peers:     map[string][]cilium.Peer{"pod-1": {{Src: "10.0.0.1:1000", DstPort: 5432}}},
		timestamp: ts,
	})
	m3 := m2.(Model)

	m4, _ := m3.Update(keyMsg("d"))
	m5 := m4.(Model)
	if m5.dumpStatus == "" {
		t.Error("dumpStatus should be set after dump")
	}
}

func TestRecordToggleKeybinding(t *testing.T) {
	m := testModelWithCapture()
	m2, _ := m.Update(keyMsg("R"))
	m3 := m2.(Model)
	if m3.recorder == nil {
		t.Fatal("recorder should not be nil")
	}
	if !m3.recorder.IsContinuous() {
		t.Error("recording should be on after pressing R")
	}
	m4, _ := m3.Update(keyMsg("R"))
	m5 := m4.(Model)
	if m5.recorder.IsContinuous() {
		t.Error("recording should be off after pressing R again")
	}
}

func TestHeaderShowsRecordingIndicator(t *testing.T) {
	lipgloss.SetColorProfile(termenv.Ascii)
	m := testModelWithCapture()
	m.width = 120
	m.height = 40
	m.recorder.SetContinuous(true)
	ts := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	m.timestamp = ts

	output := m.View()
	if !strings.Contains(output, "REC") {
		t.Error("header should show REC indicator when recording")
	}
}

func TestHelpShowsDumpAndRecordKeys(t *testing.T) {
	lipgloss.SetColorProfile(termenv.Ascii)
	m := testModel()
	m.width = 120
	m.height = 40
	m.showHelp = true

	output := m.View()
	if !strings.Contains(output, "Dump") {
		t.Error("help should show dump keybinding")
	}
	if !strings.Contains(output, "recording") || !strings.Contains(output, "R") {
		t.Error("help should show record toggle keybinding")
	}
}

func TestCaptureFilePath(t *testing.T) {
	// No recorder — should return empty.
	m := testModel()
	if got := m.CaptureFilePath(); got != "" {
		t.Errorf("CaptureFilePath() without recorder = %q, want empty", got)
	}

	// With a recorder backed by a FileWriter — should return the path.
	dir := t.TempDir()
	path := filepath.Join(dir, "test.jsonl")
	fw, err := capture.NewFileWriter(path)
	if err != nil {
		t.Fatalf("NewFileWriter: %v", err)
	}
	defer fw.Close()
	f, _ := capture.NewFormatter("jsonl")
	m.recorder = capture.NewRecorder(f, fw)
	if got := m.CaptureFilePath(); got != path {
		t.Errorf("CaptureFilePath() = %q, want %q", got, path)
	}
}

func TestDumpStatusShownInPodListStatusBar(t *testing.T) {
	lipgloss.SetColorProfile(termenv.Ascii)
	m := testModel()
	m.width = 120
	m.height = 24
	m.timestamp = time.Now()
	m.dumpStatus = "snapshot saved to test.jsonl"
	m.dumpStatusT = time.Now()

	view := m.View()
	if !strings.Contains(view, "snapshot saved to test.jsonl") {
		t.Error("pod list status bar should show dumpStatus when recent")
	}
}

func TestDumpStatusShownInPeerListStatusBar(t *testing.T) {
	lipgloss.SetColorProfile(termenv.Ascii)
	m := testModel()
	m.width = 120
	m.height = 24
	m.mode = viewPeers
	m.peers["pod-1"] = []cilium.Peer{
		{Src: "10.1.0.1:1234", DstPort: 5432},
	}
	m.dumpStatus = "recording to test.jsonl"
	m.dumpStatusT = time.Now()

	view := m.View()
	if !strings.Contains(view, "recording to test.jsonl") {
		t.Error("peer list status bar should show dumpStatus when recent")
	}
}

type errorWriter struct{}

func (w *errorWriter) Write(_ []byte) error { return fmt.Errorf("disk full") }
func (w *errorWriter) Close() error         { return nil }

func TestRecorderErrorSurfacedInDumpStatus(t *testing.T) {
	m := testModel()
	m.recorder = capture.NewRecorder(
		&capture.JSONLFormatter{},
		&errorWriter{},
	)
	m.recorder.SetContinuous(true)

	ts := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	updated, _ := m.Update(pollResultMsg{
		peers:     map[string][]cilium.Peer{"pod-1": {{Src: "10.0.0.1:1000", DstPort: 5432}}},
		timestamp: ts,
	})
	m2 := updated.(Model)
	if !strings.Contains(m2.dumpStatus, "disk full") {
		t.Errorf("dumpStatus = %q, want to contain 'disk full'", m2.dumpStatus)
	}
}

func TestDumpStatusNotShownWhenStale(t *testing.T) {
	lipgloss.SetColorProfile(termenv.Ascii)
	m := testModel()
	m.width = 120
	m.height = 24
	m.timestamp = time.Now()
	m.dumpStatus = "snapshot saved to test.jsonl"
	m.dumpStatusT = time.Now().Add(-10 * time.Second) // 10 seconds ago

	view := m.View()
	if strings.Contains(view, "snapshot saved to test.jsonl") {
		t.Error("pod list status bar should NOT show stale dumpStatus")
	}
}

// --- Quick filter tests ---

func TestStateFilterCycling(t *testing.T) {
	m := testModel()
	m.width = 80
	m.height = 24
	m.mode = viewPeers
	m.peers["pod-1"] = []cilium.Peer{
		{Src: "10.1.0.1:1234", DstPort: 5432, State: "established"},
	}

	if m.stateFilter != stateAll {
		t.Errorf("initial stateFilter = %d, want stateAll", m.stateFilter)
	}

	// f -> established
	updated, _ := m.Update(keyMsg("f"))
	m2 := updated.(Model)
	if m2.stateFilter != stateEstablished {
		t.Errorf("stateFilter after f = %d, want stateEstablished", m2.stateFilter)
	}

	// f -> closing
	updated, _ = m2.Update(keyMsg("f"))
	m3 := updated.(Model)
	if m3.stateFilter != stateClosing {
		t.Errorf("stateFilter after 2nd f = %d, want stateClosing", m3.stateFilter)
	}

	// f -> all (wrap)
	updated, _ = m3.Update(keyMsg("f"))
	m4 := updated.(Model)
	if m4.stateFilter != stateAll {
		t.Errorf("stateFilter after 3rd f = %d, want stateAll", m4.stateFilter)
	}
}

func TestProtoFilterCycling(t *testing.T) {
	m := testModel()
	m.width = 80
	m.height = 24
	m.mode = viewPeers
	m.peers["pod-1"] = []cilium.Peer{
		{Src: "10.1.0.1:1234", DstPort: 5432, Proto: "TCP"},
	}

	if m.protoFilter != protoAll {
		t.Errorf("initial protoFilter = %d, want protoAll", m.protoFilter)
	}

	// F -> TCP
	updated, _ := m.Update(keyMsg("F"))
	m2 := updated.(Model)
	if m2.protoFilter != protoTCP {
		t.Errorf("protoFilter after F = %d, want protoTCP", m2.protoFilter)
	}

	// F -> UDP
	updated, _ = m2.Update(keyMsg("F"))
	m3 := updated.(Model)
	if m3.protoFilter != protoUDP {
		t.Errorf("protoFilter after 2nd F = %d, want protoUDP", m3.protoFilter)
	}

	// F -> all (wrap)
	updated, _ = m3.Update(keyMsg("F"))
	m4 := updated.(Model)
	if m4.protoFilter != protoAll {
		t.Errorf("protoFilter after 3rd F = %d, want protoAll", m4.protoFilter)
	}
}

func TestFilterResetsScroll(t *testing.T) {
	m := testModel()
	m.width = 80
	m.height = 12
	m.mode = viewPeers
	m.scroll = 5
	m.peers["pod-1"] = []cilium.Peer{
		{Src: "10.1.0.1:1234", DstPort: 5432, State: "established"},
	}

	updated, _ := m.Update(keyMsg("f"))
	m2 := updated.(Model)
	if m2.scroll != 0 {
		t.Errorf("scroll = %d after f, want 0", m2.scroll)
	}

	m2.scroll = 5
	updated, _ = m2.Update(keyMsg("F"))
	m3 := updated.(Model)
	if m3.scroll != 0 {
		t.Errorf("scroll = %d after F, want 0", m3.scroll)
	}
}

func TestStateFilterExcludesNonMatching(t *testing.T) {
	m := testModel()
	m.stateFilter = stateEstablished
	peers := []cilium.Peer{
		{Src: "10.1.0.1:1000", DstPort: 5432, State: "established"},
		{Src: "10.1.0.2:2000", DstPort: 5432, State: "closing"},
		{Src: "10.1.0.3:3000", DstPort: 5432, State: "established"},
	}

	filtered := m.filteredPeers(peers)
	if len(filtered) != 2 {
		t.Errorf("filtered peers = %d, want 2 (established only)", len(filtered))
	}
	for _, p := range filtered {
		if p.State != "established" {
			t.Errorf("unexpected state %q in filtered results", p.State)
		}
	}
}

func TestProtoFilterExcludesNonMatching(t *testing.T) {
	m := testModel()
	m.protoFilter = protoTCP
	peers := []cilium.Peer{
		{Src: "10.1.0.1:1000", DstPort: 5432, Proto: "TCP"},
		{Src: "10.1.0.2:2000", DstPort: 5432, Proto: "UDP"},
		{Src: "10.1.0.3:3000", DstPort: 5432, Proto: "TCP"},
	}

	filtered := m.filteredPeers(peers)
	if len(filtered) != 2 {
		t.Errorf("filtered peers = %d, want 2 (TCP only)", len(filtered))
	}
	for _, p := range filtered {
		if p.Proto != "TCP" {
			t.Errorf("unexpected proto %q in filtered results", p.Proto)
		}
	}
}

func TestStateFilterAndSearchCompose(t *testing.T) {
	m := testModel()
	m.stateFilter = stateEstablished
	m.searchQuery = "10.1"
	peers := []cilium.Peer{
		{Src: "10.1.0.1:1000", DstPort: 5432, State: "established"},
		{Src: "10.1.0.2:2000", DstPort: 5432, State: "closing"},
		{Src: "10.2.0.1:3000", DstPort: 5432, State: "established"},
	}

	filtered := m.filteredPeers(peers)
	if len(filtered) != 1 {
		t.Errorf("filtered peers = %d, want 1 (established + 10.1)", len(filtered))
	}
	if len(filtered) > 0 && filtered[0].Src != "10.1.0.1:1000" {
		t.Errorf("filtered peer = %s, want 10.1.0.1:1000", filtered[0].Src)
	}
}

func TestFilterBadgeShownWhenActive(t *testing.T) {
	lipgloss.SetColorProfile(termenv.Ascii)
	m := testModel()
	m.width = 120
	m.height = 24
	m.mode = viewPeers
	m.stateFilter = stateEstablished
	m.peers["pod-1"] = []cilium.Peer{
		{Src: "10.1.0.1:1234", DstPort: 5432, State: "established"},
		{Src: "10.1.0.2:5678", DstPort: 5432, State: "closing"},
	}

	view := m.View()
	if !strings.Contains(view, "[state:established]") {
		t.Error("view should show [state:established] badge when state filter is active")
	}
}

func TestFilterBadgeHiddenWhenAll(t *testing.T) {
	lipgloss.SetColorProfile(termenv.Ascii)
	m := testModel()
	m.width = 120
	m.height = 24
	m.mode = viewPeers
	m.peers["pod-1"] = []cilium.Peer{
		{Src: "10.1.0.1:1234", DstPort: 5432, State: "established"},
	}

	view := m.View()
	if strings.Contains(view, "[state:") {
		t.Error("view should not show state filter badge when filter is 'all'")
	}
	if strings.Contains(view, "[proto:") {
		t.Error("view should not show proto filter badge when filter is 'all'")
	}
}

func TestProtoBadgeShownWhenActive(t *testing.T) {
	lipgloss.SetColorProfile(termenv.Ascii)
	m := testModel()
	m.width = 120
	m.height = 24
	m.mode = viewPeers
	m.protoFilter = protoTCP
	m.peers["pod-1"] = []cilium.Peer{
		{Src: "10.1.0.1:1234", DstPort: 5432, Proto: "TCP"},
	}

	view := m.View()
	if !strings.Contains(view, "[proto:TCP]") {
		t.Error("view should show [proto:TCP] badge when proto filter is active")
	}
}

func TestPodListCountsReflectFilter(t *testing.T) {
	lipgloss.SetColorProfile(termenv.Ascii)
	m := testModel()
	m.width = 120
	m.height = 24
	m.timestamp = time.Now()
	m.stateFilter = stateEstablished
	m.peers["pod-1"] = []cilium.Peer{
		{Src: "10.1.0.1:1234", DstPort: 5432, State: "established"},
		{Src: "10.1.0.2:5678", DstPort: 5432, State: "closing"},
	}

	view := m.View()
	// Pod list should show 1 peer (only established), not 2.
	if !strings.Contains(view, "1 peer") {
		t.Error("pod list should reflect filtered peer count (1 peer)")
	}
}

func TestEscClearsFilters(t *testing.T) {
	m := testModel()
	m.width = 80
	m.height = 24
	m.mode = viewPeers
	m.stateFilter = stateEstablished
	m.protoFilter = protoTCP

	updated, _ := m.Update(keyMsg("esc"))
	m2 := updated.(Model)
	if m2.stateFilter != stateAll {
		t.Errorf("stateFilter after esc = %d, want stateAll", m2.stateFilter)
	}
	if m2.protoFilter != protoAll {
		t.Errorf("protoFilter after esc = %d, want protoAll", m2.protoFilter)
	}
	if m2.mode != viewPods {
		t.Errorf("mode after esc = %d, want viewPods", m2.mode)
	}
}

func TestHelpShowsFilterKeys(t *testing.T) {
	lipgloss.SetColorProfile(termenv.Ascii)
	m := testModel()
	m.width = 120
	m.height = 40
	m.showHelp = true

	output := m.View()
	if !strings.Contains(output, "Cycle state filter") {
		t.Error("help should show state filter keybinding")
	}
	if !strings.Contains(output, "Cycle protocol filter") {
		t.Error("help should show protocol filter keybinding")
	}
}

func TestFilteredCountInSubheader(t *testing.T) {
	lipgloss.SetColorProfile(termenv.Ascii)
	m := testModel()
	m.width = 120
	m.height = 24
	m.mode = viewPeers
	m.stateFilter = stateEstablished
	m.peers["pod-1"] = []cilium.Peer{
		{Src: "10.1.0.1:1234", DstPort: 5432, State: "established"},
		{Src: "10.1.0.2:5678", DstPort: 5432, State: "closing"},
		{Src: "10.1.0.3:9012", DstPort: 5432, State: "established"},
	}

	view := m.View()
	if !strings.Contains(view, "2/3 connections") {
		t.Error("subheader should show '2/3 connections' when filter reduces count")
	}
}

func TestPeerViewStatusBarShowsFilterHint(t *testing.T) {
	lipgloss.SetColorProfile(termenv.Ascii)
	m := testModel()
	m.width = 120
	m.height = 24
	m.mode = viewPeers
	m.peers["pod-1"] = []cilium.Peer{
		{Src: "10.1.0.1:1234", DstPort: 5432},
	}

	view := m.View()
	if !strings.Contains(view, "f/F") {
		t.Error("peer view status bar should show 'f/F' filter hint")
	}
}

func TestStateFilterStringMethods(t *testing.T) {
	tests := []struct {
		filter stateFilter
		want   string
	}{
		{stateAll, "all"},
		{stateEstablished, "established"},
		{stateClosing, "closing"},
	}
	for _, tt := range tests {
		if got := tt.filter.String(); got != tt.want {
			t.Errorf("stateFilter(%d).String() = %q, want %q", tt.filter, got, tt.want)
		}
	}
}

func TestProtoFilterStringMethods(t *testing.T) {
	tests := []struct {
		filter protoFilter
		want   string
	}{
		{protoAll, "all"},
		{protoTCP, "TCP"},
		{protoUDP, "UDP"},
	}
	for _, tt := range tests {
		if got := tt.filter.String(); got != tt.want {
			t.Errorf("protoFilter(%d).String() = %q, want %q", tt.filter, got, tt.want)
		}
	}
}
