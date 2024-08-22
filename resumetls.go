package resumetls

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"io"
	"net"
	"reflect"

	intio "github.com/igolaizola/resumetls/internal/io"
	intnet "github.com/igolaizola/resumetls/internal/net"
	intref "github.com/igolaizola/resumetls/internal/reflect"
)

// State is buffered handshake data
type State struct {
	conn        []byte
	rand        []byte
	inSeq       [8]byte
	outSeq      [8]byte
	cipherSuite uint16
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
		return resume(tlsConn, conn, cfg, state)
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

	// TLS handshake key generation uses internally `randutil.MaybeReadByte`
	// which randomly reads one byte from the Rand reader. This makes the
	// bytes used by handshake process non-deterministic. To avoid this, we
	// override the Rand reader to avoid storing in the buffer when only one
	// byte is written.
	// See https://github.com/golang/go/blob/70491a81113e7003e314451f3e3cf134c4d41dd7/src/crypto/internal/randutil/randutil.go#L25
	randWriter := &intio.SkipOneWriter{Writer: randBuf}

	ovRand := &intio.OverrideReader{
		OverrideReader: io.TeeReader(rnd, randWriter),
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

	// TLS handshake key generation uses internally `randutil.MaybeReadByte`
	// which randomly reads one byte from the Rand reader. This makes the
	// bytes used by handshake process non-deterministic. To avoid this, we
	// override the state Rand reader to avoid reading from the buffer when only
	// one byte is read.
	// See https://github.com/golang/go/blob/70491a81113e7003e314451f3e3cf134c4d41dd7/src/crypto/internal/randutil/randutil.go#L25
	stateRandReader := &intio.SkipOneReader{Reader: bytes.NewBuffer(state.rand)}

	ovRand := &intio.OverrideReader{
		OverrideReader: io.MultiReader(stateRandReader, rnd),
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
	setState(c, state.inSeq, state.outSeq, state.cipherSuite)

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
	in, out, cipherSuite := getState(c.Conn)
	return &State{
		conn:        c.connBuffer.Bytes(),
		rand:        c.randBuffer.Bytes(),
		inSeq:       in,
		outSeq:      out,
		cipherSuite: cipherSuite,
	}
}

// setState override sequence numbers and cipher suite
func setState(conn *tls.Conn, in [8]byte, out [8]byte, cipherSuite uint16) {
	r := reflect.ValueOf(conn).Elem()
	fIn := r.FieldByName("in")
	fOut := r.FieldByName("out")

	intref.SetFieldValue(fIn, "seq", in)
	intref.SetFieldValue(fOut, "seq", out)
	//intref.SetFieldValue(r, "cipherSuite", cipherSuite)
}

// getState obtains sequence numbers and cipher suite
func getState(conn *tls.Conn) ([8]byte, [8]byte, uint16) {
	r := reflect.ValueOf(conn).Elem()
	fIn := r.FieldByName("in")
	in := intref.FieldToInterface(fIn, "seq").([8]byte)

	fOut := r.FieldByName("out")
	out := intref.FieldToInterface(fOut, "seq").([8]byte)
	cipherSuite := intref.FieldToInterface(r, "cipherSuite").(uint16)

	return in, out, cipherSuite
}
