package tui

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
