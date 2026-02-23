package display

import (
	"fmt"
	"io"
	"strings"
	"time"
)

const (
	bold   = "\033[1m"
	dim    = "\033[2m"
	green  = "\033[0;32m"
	yellow = "\033[0;33m"
	reset  = "\033[0m"
)

type PodStatus struct {
	Name   string
	Active bool
	Peers  []string
}

func RenderCycle(w io.Writer, pods []PodStatus, port int, now time.Time, termWidth int) {
	// Separator
	fmt.Fprintf(w, "%s%s%s\n", dim, strings.Repeat("-", termWidth), reset)

	active := 0
	total := 0
	for _, p := range pods {
		if p.Active {
			active++
		}
		total += len(p.Peers)
	}

	ts := now.Format("2006-01-02T15:04:05Z")
	if active == 0 {
		fmt.Fprintf(w, "%speers on :%d%s  %s%s%s  %sall pods exited%s  %s%d connections%s\n",
			bold, port, reset, dim, ts, reset, yellow, reset, bold, total, reset)
	} else {
		fmt.Fprintf(w, "%speers on :%d%s  %s%s%s  %s%d/%d active%s  %s%d connections%s\n",
			bold, port, reset, dim, ts, reset, green, active, len(pods), reset, bold, total, reset)
	}
	fmt.Fprintln(w)

	for _, p := range pods {
		if p.Active {
			fmt.Fprintf(w, "  %s[active]%s  %s%s%s  %s(%d peers)%s\n",
				green, reset, bold, p.Name, reset, dim, len(p.Peers), reset)
		} else {
			fmt.Fprintf(w, "  %s[exited]%s  %s%s%s  %s(%d peers)%s\n",
				yellow, reset, bold, p.Name, reset, dim, len(p.Peers), reset)
		}
		for _, peer := range p.Peers {
			fmt.Fprintf(w, "           %s%s%s\n", dim, peer, reset)
		}
	}
	fmt.Fprintln(w)
}

func WriteReport(w io.Writer, pods []PodStatus, port int, now time.Time) {
	ts := now.Format("2006-01-02T15:04:05Z")
	fmt.Fprintf(w, "peers on :%d  %s\n\n", port, ts)

	for _, p := range pods {
		if p.Active {
			fmt.Fprintf(w, "[active]  %s\n", p.Name)
		} else {
			fmt.Fprintf(w, "[exited]  %s\n", p.Name)
		}
		for _, peer := range p.Peers {
			fmt.Fprintf(w, "           %s\n", peer)
		}
		fmt.Fprintln(w)
	}
}
