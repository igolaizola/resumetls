package net

import (
	"io"
	"net"
)

// OverrideConn is an net.Conn implementation with an extra reader and writer that override when not nil
type OverrideConn struct {
	net.Conn
	OverrideReader io.Reader
	OverrideWriter io.Writer
}

// Read implements net.Conn.Read
func (c *OverrideConn) Read(p []byte) (n int, err error) {
	if c.OverrideReader != nil {
		return c.OverrideReader.Read(p)
	}
	return c.Conn.Read(p)
}

// Write implements net.Conn.Write
func (c *OverrideConn) Write(p []byte) (n int, err error) {
	if c.OverrideWriter != nil {
		return c.OverrideWriter.Write(p)
	}
	return c.Conn.Write(p)
}
