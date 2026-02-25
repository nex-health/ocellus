package capture

// DumpOnce formats and writes a single snapshot.
func DumpOnce(f Formatter, w Writer, snap Snapshot) error {
	data, err := f.FormatSnapshot(snap)
	if err != nil {
		return err
	}
	return w.Write(data)
}
