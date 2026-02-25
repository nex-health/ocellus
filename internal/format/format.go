package format

import "fmt"

// Bytes formats a byte count as a compact human-readable string.
func Bytes(b uint64) string {
	switch {
	case b < 1024:
		return fmt.Sprintf("%d B", b)
	case b < 1024*1024:
		return fmt.Sprintf("%.1f K", float64(b)/1024)
	case b < 1024*1024*1024:
		return fmt.Sprintf("%.1f M", float64(b)/(1024*1024))
	default:
		return fmt.Sprintf("%.1f G", float64(b)/(1024*1024*1024))
	}
}
