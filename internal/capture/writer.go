package capture

import (
	"io"
	"os"
)

// Writer handles output to a destination.
type Writer interface {
	Write(data []byte) error
	Close() error
}

// FileWriter appends to a file.
type FileWriter struct {
	f *os.File
}

// NewFileWriter opens a file for appending, creating it if needed.
func NewFileWriter(path string) (*FileWriter, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, err
	}
	return &FileWriter{f: f}, nil
}

func (w *FileWriter) Write(data []byte) error {
	_, err := w.f.Write(data)
	return err
}

func (w *FileWriter) Close() error {
	return w.f.Close()
}

// Path returns the file path.
func (w *FileWriter) Path() string {
	return w.f.Name()
}

// StreamWriter writes to an io.Writer (e.g., os.Stdout).
type StreamWriter struct {
	w io.Writer
}

// NewStreamWriter wraps an io.Writer.
func NewStreamWriter(w io.Writer) *StreamWriter {
	return &StreamWriter{w: w}
}

func (w *StreamWriter) Write(data []byte) error {
	_, err := w.w.Write(data)
	return err
}

func (w *StreamWriter) Close() error {
	if c, ok := w.w.(io.Closer); ok {
		return c.Close()
	}
	return nil
}
