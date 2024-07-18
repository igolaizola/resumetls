package io

import (
	"io"
)

// OverrideReader is an io.Reader implementation with an extra reader that overrides when not nil
type OverrideReader struct {
	io.Reader
	OverrideReader io.Reader
}

// Read implements io.Reader.Read
func (r *OverrideReader) Read(p []byte) (n int, err error) {
	if r.OverrideReader != nil {
		return r.OverrideReader.Read(p)
	}
	return r.Reader.Read(p)
}

// SkipOneReader is an io.Reader implementation that skips reading when only
// one byte is requested.
type SkipOneReader struct {
	io.Reader
}

// Read implements io.Reader.Read
func (r *SkipOneReader) Read(p []byte) (n int, err error) {
	if len(p) == 1 {
		return 1, nil
	}
	return r.Reader.Read(p)
}

// SkipOneWriter is an io.Writer implementation that skips writing when only
// one byte is written.
type SkipOneWriter struct {
	io.Writer
}

// Write implements io.Writer.Write
func (r *SkipOneWriter) Write(p []byte) (n int, err error) {
	if len(p) == 1 {
		return 1, nil
	}
	return r.Writer.Write(p)
}
