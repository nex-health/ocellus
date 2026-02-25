package capture

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestFileWriter(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	w, err := NewFileWriter(path)
	if err != nil {
		t.Fatalf("NewFileWriter error: %v", err)
	}

	if err := w.Write([]byte("line 1\n")); err != nil {
		t.Fatalf("Write error: %v", err)
	}
	if err := w.Write([]byte("line 2\n")); err != nil {
		t.Fatalf("Write error: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close error: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile error: %v", err)
	}
	if string(data) != "line 1\nline 2\n" {
		t.Errorf("file content = %q, want %q", string(data), "line 1\nline 2\n")
	}
}

func TestFileWriterAppends(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	w1, _ := NewFileWriter(path)
	_ = w1.Write([]byte("first\n"))
	_ = w1.Close()

	w2, _ := NewFileWriter(path)
	_ = w2.Write([]byte("second\n"))
	_ = w2.Close()

	data, _ := os.ReadFile(path)
	if string(data) != "first\nsecond\n" {
		t.Errorf("file content = %q, want appended", string(data))
	}
}

func TestFileWriterPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.jsonl")
	w, err := NewFileWriter(path)
	if err != nil {
		t.Fatalf("NewFileWriter error: %v", err)
	}
	defer w.Close()
	if w.Path() != path {
		t.Errorf("Path() = %q, want %q", w.Path(), path)
	}
}

func TestStreamWriter(t *testing.T) {
	var buf bytes.Buffer
	w := NewStreamWriter(&buf)

	if err := w.Write([]byte("hello\n")); err != nil {
		t.Fatalf("Write error: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close error: %v", err)
	}

	if buf.String() != "hello\n" {
		t.Errorf("output = %q, want %q", buf.String(), "hello\n")
	}
}
