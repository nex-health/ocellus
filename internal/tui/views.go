package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/nex-health/ocellus/internal/cilium"
	"github.com/nex-health/ocellus/internal/format"
)

// renderStatusBar writes the status bar with polling indicator.
func (m Model) renderStatusBar(b *strings.Builder, w int, keys string) {
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
	padLen := max(w-lipgloss.Width(keys)-lipgloss.Width(statusIndicator)-2, 0)
	statusText := keys + strings.Repeat(" ", padLen) + statusIndicator
	b.WriteString(statusBarStyle.Width(w).Render(statusText))
}

// formatPeerBytes formats the bytes display for a peer.
func formatPeerBytes(p cilium.Peer) string {
	switch {
	case p.RxBytes > 0 || p.TxBytes > 0:
		return format.Bytes(p.RxBytes) + "/" + format.Bytes(p.TxBytes)
	case p.Bytes > 0:
		return format.Bytes(p.Bytes)
	default:
		return "—"
	}
}

// renderPeerSubheader writes the peer view subheader with filter indicators.
func (m Model) renderPeerSubheader(b *strings.Builder, selectedName string, totalPeers, filteredPeers int) {
	countLabel := fmt.Sprintf("%d connections", filteredPeers)
	if filteredPeers != totalPeers {
		countLabel = fmt.Sprintf("%d/%d connections", filteredPeers, totalPeers)
	}
	subheader := fmt.Sprintf("Peers for %s:   %s", selectedName, peerCountStyle.Render(countLabel))
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
	keys := fmt.Sprintf("  %s quit  %s navigate  %s select  %s next active  %s pause  %s dump  %s record  %s help",
		statusBarKeyStyle.Render("q"),
		statusBarKeyStyle.Render("j/k"),
		statusBarKeyStyle.Render("enter"),
		statusBarKeyStyle.Render("tab"),
		statusBarKeyStyle.Render("p"),
		statusBarKeyStyle.Render("d"),
		statusBarKeyStyle.Render("R"),
		statusBarKeyStyle.Render("?"))
	m.renderStatusBar(&b, w, keys)

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
	m.renderPeerSubheader(&b, selected.Name, len(allPeers), len(peers))

	if len(peers) == 0 {
		b.WriteString(detailPeerStyle.Render("(none)"))
		b.WriteString("\n")
	} else {
		// Compute column widths.
		peerColW := len("Peer Address:Port")
		localColW := len("Local Address:Port")
		bytesColW := len("Rx/Tx")
		bytesStrs := make([]string, len(peers))
		for i, p := range peers {
			if len(p.Src) > peerColW {
				peerColW = len(p.Src)
			}
			local := fmt.Sprintf("%s:%d", selected.IP, p.DstPort)
			if len(local) > localColW {
				localColW = len(local)
			}
			bs := formatPeerBytes(p)
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
		m.renderStatusBar(&b, w, keys)
	}

	return b.String()
}
