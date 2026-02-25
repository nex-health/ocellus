package capture

// Recorder orchestrates formatting, writing, and event detection.
type Recorder struct {
	formatter  Formatter
	writer     Writer
	prev       *Snapshot
	continuous bool
}

// NewRecorder creates a Recorder with the given formatter and writer.
func NewRecorder(f Formatter, w Writer) *Recorder {
	return &Recorder{
		formatter: f,
		writer:    w,
	}
}

// OnPoll processes a new poll snapshot. If continuous recording is on,
// it writes the snapshot. It always diffs against the previous snapshot
// and writes any detected events.
func (r *Recorder) OnPoll(snap Snapshot) error {
	events := Diff(r.prev, snap)

	if r.continuous {
		data, err := r.formatter.FormatSnapshot(snap)
		if err != nil {
			return err
		}
		if err := r.writer.Write(data); err != nil {
			return err
		}
	}

	for _, e := range events {
		data, err := r.formatter.FormatEvent(e)
		if err != nil {
			return err
		}
		if err := r.writer.Write(data); err != nil {
			return err
		}
	}

	r.prev = &snap
	return nil
}

// DumpSnapshot writes a single snapshot to the writer (on-demand capture).
func (r *Recorder) DumpSnapshot(snap Snapshot) error {
	data, err := r.formatter.FormatSnapshot(snap)
	if err != nil {
		return err
	}
	return r.writer.Write(data)
}

// SetContinuous toggles continuous recording.
func (r *Recorder) SetContinuous(on bool) {
	r.continuous = on
}

// IsContinuous returns whether continuous recording is enabled.
func (r *Recorder) IsContinuous() bool {
	return r.continuous
}

// Close flushes and closes the underlying writer.
func (r *Recorder) Close() error {
	return r.writer.Close()
}
