package cilium

import (
	"fmt"
	"sort"
	"strings"
)

// ParseCTOutput parses cilium bpf ct list output and returns unique peer
// addresses with active TCP IN connections to the given podIP:port.
func ParseCTOutput(output string, podIP string, port int) []string {
	target := fmt.Sprintf("-> %s:%d ", podIP, port)
	seen := make(map[string]bool)
	var peers []string

	for _, line := range strings.Split(output, "\n") {
		if !strings.HasPrefix(line, "TCP IN ") {
			continue
		}
		if !strings.Contains(line, target) {
			continue
		}
		if strings.Contains(line, "RxClosing") {
			continue
		}

		// Extract source: "TCP IN <src> -> <dst> ..."
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		src := fields[2] // e.g. "10.4.166.193:52628"

		if !seen[src] {
			seen[src] = true
			peers = append(peers, src)
		}
	}

	sort.Strings(peers)
	return peers
}
