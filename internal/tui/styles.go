package tui

import "github.com/charmbracelet/lipgloss"

var (
	colorGreen    = lipgloss.AdaptiveColor{Light: "#166534", Dark: "#22c55e"}
	colorRed      = lipgloss.AdaptiveColor{Light: "#991b1b", Dark: "#ef4444"}
	colorYellow   = lipgloss.AdaptiveColor{Light: "#92400e", Dark: "#eab308"}
	colorCyan     = lipgloss.AdaptiveColor{Light: "#0e7490", Dark: "#22d3ee"}
	colorDim      = lipgloss.AdaptiveColor{Light: "#737373", Dark: "#a3a3a3"}
	colorBg       = lipgloss.AdaptiveColor{Light: "#d4d4d8", Dark: "#27272a"}
	colorFg       = lipgloss.AdaptiveColor{Light: "#18181b", Dark: "#fafafa"}
	colorSelectBg = lipgloss.AdaptiveColor{Light: "#bfdbfe", Dark: "#1e3a5f"}
	colorSelectFg = lipgloss.AdaptiveColor{Light: "#1e3a8a", Dark: "#e0f2fe"}

	headerStyle = lipgloss.NewStyle().
			Background(colorBg).
			Foreground(colorFg).
			Padding(0, 1)

	headerBrandStyle = lipgloss.NewStyle().
				Background(colorBg).
				Foreground(colorFg).
				Bold(true)

	headerContextStyle = lipgloss.NewStyle().
				Background(colorBg).
				Foreground(colorCyan)

	headerTargetStyle = lipgloss.NewStyle().
				Background(colorBg).
				Foreground(colorFg).
				Bold(true)

	headerDimStyle = lipgloss.NewStyle().
			Background(colorBg).
			Foreground(colorDim)

	headerStatsStyle = lipgloss.NewStyle().
				Background(colorBg).
				Foreground(colorGreen)

	headerRateStyle = lipgloss.NewStyle().
			Background(colorBg).
			Foreground(colorYellow)

	activeIcon = lipgloss.NewStyle().Foreground(colorGreen).SetString("●")
	exitedIcon = lipgloss.NewStyle().Foreground(colorYellow).SetString("●")

	rowStyle = lipgloss.NewStyle().Padding(0, 1)

	selectedRowStyle = lipgloss.NewStyle().
				Padding(0, 1).
				Background(colorSelectBg).
				Foreground(colorSelectFg).
				Bold(true)

	peerCountStyle = lipgloss.NewStyle().Foreground(colorDim)

	detailHeaderStyle = lipgloss.NewStyle().
				Bold(true).
				Padding(0, 1)

	columnHeaderStyle = lipgloss.NewStyle().
				Bold(true).
				Padding(0, 3)

	detailPeerStyle = lipgloss.NewStyle().
			Padding(0, 3)

	statusBarStyle = lipgloss.NewStyle().
			Background(colorBg).
			Foreground(colorDim).
			Padding(0, 1)

	statusBarKeyStyle = lipgloss.NewStyle().
				Background(colorBg).
				Foreground(colorFg).
				Bold(true)

	dividerStyle = lipgloss.NewStyle().Foreground(colorDim)

	stateEstablishedStyle = lipgloss.NewStyle().Foreground(colorGreen)
	stateClosingStyle     = lipgloss.NewStyle().Foreground(colorRed)

	peerCountActiveStyle = lipgloss.NewStyle().Bold(true)

	sortArrowStyle = lipgloss.NewStyle().Foreground(colorGreen).Bold(true)

	searchMatchStyle = lipgloss.NewStyle().Foreground(colorYellow).Bold(true)

	searchBarStyle = lipgloss.NewStyle().
			Background(colorBg).
			Foreground(colorFg).
			Padding(0, 1)

	pollingStyle = lipgloss.NewStyle().
			Background(colorBg).
			Foreground(colorGreen).
			Bold(true)

	pausedStyle = lipgloss.NewStyle().
			Background(colorBg).
			Foreground(colorYellow).
			Bold(true)

	errorStyle = lipgloss.NewStyle().
			Background(colorBg).
			Foreground(colorRed).
			Bold(true)
)
