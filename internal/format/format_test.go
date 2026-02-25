package format

import "testing"

func TestFormatBytes(t *testing.T) {
	tests := []struct {
		input uint64
		want  string
	}{
		{0, "0 B"},
		{100, "100 B"},
		{1023, "1023 B"},
		{1024, "1.0 K"},
		{1536, "1.5 K"},
		{1048576, "1.0 M"},
		{1073741824, "1.0 G"},
		{10737418240, "10.0 G"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := Bytes(tt.input)
			if got != tt.want {
				t.Errorf("Bytes(%d) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
