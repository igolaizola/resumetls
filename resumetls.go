package resumetls

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"io"
	"net"
	"reflect"

	intio "github.com/igolaizola/resume-tls/internal/io"
	intnet "github.com/igolaizola/resume-tls/internal/net"
	intref "github.com/igolaizola/resume-tls/internal/reflect"
)

// State is buffered handshake data
type State struct {
	conn   []byte
	rand   []byte
	inSeq  [8]byte
	outSeq [8]byte
}

// Conn resumable tls conn
type Conn struct {
	handshaked   bool
	overrideRand *intio.OverrideReader
	overrideConn *intnet.OverrideConn
	connBuffer   *bytes.Buffer
	randBuffer   *bytes.Buffer
	*tls.Conn
}

// Client returns a resumable tls client conn
func Client(conn net.Conn, cfg *tls.Config, state *State) (*Conn, error) {
	return newConn(tls.Client, conn, cfg, state)
}

// Server returns a resumable tls server conn
func Server(conn net.Conn, cfg *tls.Config, state *State) (*Conn, error) {
	return newConn(tls.Server, conn, cfg, state)
}

// newConn returns a resumable tls conn
func newConn(tlsConn func(net.Conn, *tls.Config) *tls.Conn, conn net.Conn, cfg *tls.Config, state *State) (*Conn, error) {
	if state != nil {
		var err error
		// Client hello message sometimes consumes more random bytes than the
		// ones provided by the state. Probably due to how elliptic curves keys
		// are generated.
		// We have tested empirically that retrying 10 times is enough to get a
		// successful handshake. Here, we set the limit to 20 to be on the safe
		// side.
		for i := 0; i < 20; i++ {
			var c *Conn
			c, err = resume(tlsConn, conn, cfg, state)
			if err == nil {
				return c, err
			}
		}
		return nil, err
	}
	return initialize(tlsConn, conn, cfg), nil
}

// initializes a resumable TLS client conn
func initialize(tlsConn func(net.Conn, *tls.Config) *tls.Conn, conn net.Conn, cfg *tls.Config) *Conn {
	connBuf := &bytes.Buffer{}
	randBuf := &bytes.Buffer{}

	rnd := cfg.Rand
	if rnd == nil {
		rnd = rand.Reader
	}
	ovRand := &intio.OverrideReader{
		OverrideReader: io.TeeReader(rnd, randBuf),
		Reader:         rnd,
	}
	ovConn := &intnet.OverrideConn{
		Conn:           conn,
		OverrideReader: io.TeeReader(conn, connBuf),
	}

	cfg.Rand = ovRand
	return &Conn{
		overrideConn: ovConn,
		overrideRand: ovRand,
		connBuffer:   connBuf,
		randBuffer:   randBuf,
		Conn:         tlsConn(ovConn, cfg),
	}
}

// resume resumes a resumable TLS client conn
func resume(tlsConn func(net.Conn, *tls.Config) *tls.Conn, conn net.Conn, cfg *tls.Config, state *State) (*Conn, error) {
	rnd := cfg.Rand
	if rnd == nil {
		rnd = rand.Reader
	}
	ovRand := &intio.OverrideReader{
		OverrideReader: io.MultiReader(bytes.NewBuffer(state.rand), rnd),
		Reader:         rnd,
	}
	ovConn := &intnet.OverrideConn{
		Conn:           conn,
		OverrideReader: io.MultiReader(bytes.NewBuffer(state.conn), conn),
		OverrideWriter: io.Discard,
	}
	cfg.Rand = ovRand

	c := tlsConn(ovConn, cfg)
	if err := c.Handshake(); err != nil {
		return nil, err
	}
	ovRand.OverrideReader = nil
	ovConn.OverrideReader = nil
	ovConn.OverrideWriter = nil
	setSeq(c, state.inSeq, state.outSeq)

	return &Conn{
		handshaked: true,
		connBuffer: bytes.NewBuffer(state.conn),
		randBuffer: bytes.NewBuffer(state.rand),
		Conn:       c,
	}, nil
}

// Handshake overrides tls handshakes
func (c *Conn) Handshake() error {
	if c.handshaked {
		return nil
	}
	if err := c.Conn.Handshake(); err != nil {
		c.connBuffer = &bytes.Buffer{}
		c.randBuffer = &bytes.Buffer{}
		return err
	}
	c.handshaked = true
	c.overrideRand.OverrideReader = nil
	c.overrideConn.OverrideReader = nil
	return nil
}

// State gets the data in order to resume a connection
func (c *Conn) State() *State {
	in, out := getSeq(c.Conn)
	return &State{
		conn:   c.connBuffer.Bytes(),
		rand:   c.randBuffer.Bytes(),
		inSeq:  in,
		outSeq: out,
	}
}

// setSeq override sequence number
func setSeq(conn *tls.Conn, in [8]byte, out [8]byte) {
	r := reflect.ValueOf(conn).Elem()
	fIn := r.FieldByName("in")
	fOut := r.FieldByName("out")

	intref.SetFieldValue(fIn, "seq", in)
	intref.SetFieldValue(fOut, "seq", out)
}

// getSeq obtains sequence numbers
func getSeq(conn *tls.Conn) ([8]byte, [8]byte) {
	r := reflect.ValueOf(conn).Elem()
	fIn := r.FieldByName("in")
	in := intref.FieldToInterface(fIn, "seq").([8]byte)

	fOut := r.FieldByName("out")
	out := intref.FieldToInterface(fOut, "seq").([8]byte)

	return in, out
}
