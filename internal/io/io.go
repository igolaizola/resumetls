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
