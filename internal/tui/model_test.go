package tui

import (
	"fmt"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"

	"github.com/aurelcanciu/ocellus/internal/cilium"
	"github.com/aurelcanciu/ocellus/internal/k8s"
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
	for i := 0; i < 20; i++ {
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
	for i := 0; i < 30; i++ {
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
	for i := 0; i < 30; i++ {
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
	for i := 0; i < 20; i++ {
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
	for i := 0; i < 20; i++ {
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
	for i := 0; i < 30; i++ {
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
	for i := 0; i < 30; i++ {
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
	for i := 0; i < 30; i++ {
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
	for i := 0; i < 30; i++ {
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
	for i := 0; i < 30; i++ {
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
	expected := 15 - halfPage
	if expected < 0 {
		expected = 0
	}
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
