package resumetls

import (
	"bytes"
	"crypto/tls"
	"net"
	"testing"
)

var cert = `-----BEGIN CERTIFICATE-----
MIIDADCCAeigAwIBAgIRAMlZFfrjDjpriu1r+XIr1kwwDQYJKoZIhvcNAQELBQAw
EjEQMA4GA1UEChMHQWNtZSBDbzAeFw0xODA4MDIxMTI0MTlaFw0xOTA4MDIxMTI0
MTlaMBIxEDAOBgNVBAoTB0FjbWUgQ28wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
ggEKAoIBAQDHYGCQkL4xc4djNNtjWcuPAGLmiRLI+uompmccJ7f9vUZgu/gO9oVS
nQlVRNX4LS0TnZjyQMso+9ZNt9sdyDohkMVmS0O27kD9gz2Pz+otYg0w4TVX0pJp
c3jwvSoXdqNxrj+Fk9aptIFsfipN2cE7uFA40+rZSlyND+lSB/VvNKILSrp6Ugmo
CpRRFJ0O8VjYV+qU7RZh9HFIvtW6w9uLeN2jD+k7VGVt6hADpdoSzQiAerZ5+8ee
IcmAj/G5COGbGAnbuy73/Bmo9b728UXo6b+7GdyXYij/pev/0OcIoT7WKFQJJyVz
owc+yyEHhKpuKqCy9KNzPQqm7je//BptAgMBAAGjUTBPMA4GA1UdDwEB/wQEAwIF
oDATBgNVHSUEDDAKBggrBgEFBQcDATAMBgNVHRMBAf8EAjAAMBoGA1UdEQQTMBGC
CWxvY2FsaG9zdIcEfwAAATANBgkqhkiG9w0BAQsFAAOCAQEAlDF2c4ktrz1BJcQL
PhyynqOmLCJiPw/A9vSCOuaH2RduHufiO80RKW9KRiLsAAvSToAsFrTNlTL3Jdjp
UnWjal+gMh3fU+Fw3lGlq/UeYxMjZsTATazy2D2dJWwv0PUWo7dE0w/Thh1SdhEU
cNpoIDTsrnfa4P300XK+ej5A6gVYa++adAh3QdjLAzOfDxIInMwinMIQy9kACPvd
XNZ4AfD+wsH0dHTFPr5k12ZJbPMljCFe/rmbDoEpxOwimBcnRohEgOIbKjwEUXRi
B+q7AnJ0Q1rK/J7ikSDFBBGlg8wHWz+FCINmyyv62qClErI4aA/WN6+ilINJV/gG
qgNGqQ==
-----END CERTIFICATE-----`

var key = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAx2BgkJC+MXOHYzTbY1nLjwBi5okSyPrqJqZnHCe3/b1GYLv4
DvaFUp0JVUTV+C0tE52Y8kDLKPvWTbfbHcg6IZDFZktDtu5A/YM9j8/qLWINMOE1
V9KSaXN48L0qF3ajca4/hZPWqbSBbH4qTdnBO7hQONPq2UpcjQ/pUgf1bzSiC0q6
elIJqAqUURSdDvFY2FfqlO0WYfRxSL7VusPbi3jdow/pO1RlbeoQA6XaEs0IgHq2
efvHniHJgI/xuQjhmxgJ27su9/wZqPW+9vFF6Om/uxncl2Io/6Xr/9DnCKE+1ihU
CSclc6MHPsshB4SqbiqgsvSjcz0Kpu43v/wabQIDAQABAoIBADbktjGXaIY9BL2v
w+eqxXzt4k0O2Hk1fFp/3kvGM8ZM4p+noTidbz+7tOIhPbhC1/Japc2tQUJbdDmZ
sV6VzkuHjJIJju9C0en6xGxgFl3AbVlT6FfxxhX6kQXXT0t+gqm+DAc/GQ9If4nb
gtJEbgt/R7cdwb9p1emQw/Ct+ElRe+xTZ36Vw1wgyLUmJJB3IAj5JTqeBwqFQOvt
fV3zuS/zzzfXuhShwJMpsdHVJJzULeZPU1nhxAeTKGSF8XwBOL0hSL4ikS0s/U0P
RoTL4flKsC3YwFOVq3Cn8bZW0xI5h/UmISJhkyj8th6PV72NNCBJ5ogLAr24TqH4
Emvj14ECgYEA1uLZXRue7vScYbpEUud+crM6ejBNOhib968J/Au1yf6aS9dgALVP
MaZXg2GKRJWLHr3om4vJOUP14970NkJKlCkqJD8uUjKtGchcaNELPQjwM7HjmBAW
VHANjHFJTEIGG/v9wwVE/ZUf9ljqE7jFA+DkJ5GrSfomwU1eKEthmQkCgYEA7YXc
9zD/dmHg4LpbBP7R8syC4Ijl+ux/huuBh6GIbyLKCagtL3TFSNInDPO6rT1YdgLZ
7WZSXaQ98aq2Q0vNRiXMccrsx6nPj20arRaZROZgz7s5W62Eexbz/b5rUrAuXzJF
CVF6raZUxUKlF1b2ybc93ScqqjfWfoyZebE8w0UCgYEApxz+O+maHW2AHIR2VB8R
+HOoG5Rqyq6OxP2Mf0ZAFxn4ttiFIaffMdaSImt90z6VVdANEMKSOAXBOXiPZY8C
XtzwmAXGqUgd1Ho8W4uO+OV1oE5MmFqScxI9hyYnAbYq+CJtw/faIneRxsx5JeNA
3HZOGPOxSTPQZe4cNqwA97kCgYBfVvYk+rPwDsW3LtZOIQKg1NpLymeV2swtmeZ6
TKp5AZvbWHgarmJqIoCuQD7UPuV9KRPUqNey4rRChuV2Cb0xxQZVPsDgPBcmWQL2
KzYGY/rEJ0CUvgeJaOMzHPXzUOisKX9wiBYYEcXBEEk4Hx4cRcM9O/VyMcuVLFaG
dFARiQKBgQCHKrb0SzYVnaEWFR+GP+sJMfxrhq/N8m+WcCpoQ/UIvguMWmFKtVtC
WVTd3XNizIpuNpDgGI4qvIwmEs7UhAzemxasYoP3y3FO2dT0QGC+T1SX/BsW6AiO
fi06KUiLh/4rJtf2wph2wN8SPAY4yQkopFlDYTJNmhhYsKTGIhrpww==
-----END RSA PRIVATE KEY-----`

var ciphers = []struct {
	name   string
	cipher uint16
}{
	{
		name:   "TLS_RSA_WITH_RC4_128_SHA",
		cipher: tls.TLS_RSA_WITH_RC4_128_SHA,
	},
	{
		name:   "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
		cipher: tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
	},
	{
		name:   "TLS_RSA_WITH_AES_128_CBC_SHA",
		cipher: tls.TLS_RSA_WITH_AES_128_CBC_SHA,
	},
	{
		name:   "TLS_RSA_WITH_AES_256_CBC_SHA",
		cipher: tls.TLS_RSA_WITH_AES_256_CBC_SHA,
	},
	{
		name:   "TLS_RSA_WITH_AES_128_CBC_SHA256",
		cipher: tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
	},
	{
		name:   "TLS_RSA_WITH_AES_128_GCM_SHA256",
		cipher: tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
	},
	{
		name:   "TLS_RSA_WITH_AES_256_GCM_SHA384",
		cipher: tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
	},
	{
		name:   "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
		cipher: tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
	},
	{
		name:   "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
		cipher: tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
	},
	{
		name:   "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
		cipher: tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	},
	{
		name:   "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
		cipher: tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
	},
	{
		name:   "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
		cipher: tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
	},
	{
		name:   "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
		cipher: tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	},
	{
		name:   "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
		cipher: tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	},
	{
		name:   "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
		cipher: tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
	},
	{
		name:   "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
		cipher: tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
	},
	{
		name:   "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		cipher: tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	},
	{
		name:   "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
		cipher: tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	},
	{
		name:   "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
		cipher: tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	},
	{
		name:   "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
		cipher: tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	},
	{
		name:   "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
		cipher: tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	},
	{
		name:   "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
		cipher: tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
	},
	{
		name:   "TLS_AES_128_GCM_SHA256",
		cipher: tls.TLS_AES_128_GCM_SHA256,
	},
	{
		name:   "TLS_AES_256_GCM_SHA384",
		cipher: tls.TLS_AES_256_GCM_SHA384,
	},
	{
		name:   "TLS_CHACHA20_POLY1305_SHA256",
		cipher: tls.TLS_CHACHA20_POLY1305_SHA256,
	},
}

func TestClient(t *testing.T) {
	for _, tt := range ciphers {
		t.Run(tt.name, func(t *testing.T) {
			for i := 0; i < 100; i++ {
				testClient(t, tt.cipher)
			}
		})
	}
}

func testClient(t *testing.T, cipher uint16) {
	sConn, cConn := net.Pipe()

	pair, err := tls.X509KeyPair([]byte(cert), []byte(key))
	if err != nil {
		t.Fatal(err)
	}

	srv := tls.Server(sConn, &tls.Config{
		Certificates: []tls.Certificate{pair},
		CipherSuites: []uint16{cipher},
	})

	cli, err := Client(cConn, &tls.Config{
		InsecureSkipVerify: true,
		CipherSuites:       []uint16{cipher},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Launch server in another goroutine
	go func() {
		if err := srv.Handshake(); err != nil {
			panic(err)
		}
		// Loop of read write
		for i := 0; i < 2; i++ {
			recv := make([]byte, 1024)
			n, err := srv.Read(recv)
			if err != nil {
				panic(err)
			}

			if _, err := srv.Write(recv[:n]); err != nil {
				panic(err)
			}
		}
	}()

	// Initial handshake
	if err := cli.Handshake(); err != nil {
		t.Fatal(err)
	}

	// Test write and read
	message := []byte("Hello")
	if _, err := cli.Write(message); err != nil {
		t.Fatal(err)
	}

	recv := make([]byte, 1024)
	n, err := cli.Read(recv)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(message, recv[:n]) {
		t.Errorf("messages missmatch: %s != %s", message, recv[:n])
	}

	// Extract TLS state
	state := cli.State()

	// Resume client
	cli2, err := Client(cConn, &tls.Config{
		InsecureSkipVerify: true,
		CipherSuites:       []uint16{cipher},
	}, state)
	if err != nil {
		t.Fatal(err)
	}

	// Test write and read on resumed client
	if _, err := cli2.Write(message); err != nil {
		t.Fatal(err)
	}

	recv = make([]byte, 1024)
	n, err = cli2.Read(recv)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(message, recv[:n]) {
		t.Errorf("messages missmatch: %s != %s", message, recv[:n])
	}
}

func TestServer(t *testing.T) {
	for _, tt := range ciphers {
		t.Run(tt.name, func(t *testing.T) {
			for i := 0; i < 100; i++ {
				testServer(t, tt.cipher)
			}
		})
	}
}

func testServer(t *testing.T, cipher uint16) {
	sConn, cConn := net.Pipe()

	pair, err := tls.X509KeyPair([]byte(cert), []byte(key))
	if err != nil {
		t.Fatal(err)
	}

	cli := tls.Client(sConn, &tls.Config{
		InsecureSkipVerify: true,
		CipherSuites:       []uint16{cipher},
	})

	srv, err := Server(cConn, &tls.Config{
		InsecureSkipVerify: true,
		Certificates:       []tls.Certificate{pair},
		CipherSuites:       []uint16{cipher},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Launch client in another goroutine
	go func() {
		if err := cli.Handshake(); err != nil {
			panic(err)
		}
		// Loop of read write
		for i := 0; i < 2; i++ {
			recv := make([]byte, 1024)
			n, err := cli.Read(recv)
			if err != nil {
				panic(err)
			}

			if _, err := cli.Write(recv[:n]); err != nil {
				panic(err)
			}
		}
	}()

	// Initial handshake
	if err := srv.Handshake(); err != nil {
		t.Fatal(err)
	}

	// Test write and read
	message := []byte("Hello")
	if _, err := srv.Write(message); err != nil {
		t.Fatal(err)
	}

	recv := make([]byte, 1024)
	n, err := srv.Read(recv)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(message, recv[:n]) {
		t.Errorf("messages missmatch: %s != %s", message, recv[:n])
	}

	// Extract TLS state
	state := srv.State()

	// Resume server
	srv2, err := Server(cConn, &tls.Config{
		InsecureSkipVerify: true,
		Certificates:       []tls.Certificate{pair},
		CipherSuites:       []uint16{cipher},
	}, state)
	if err != nil {
		t.Fatal(err)
	}

	// Test write and read on resumed client
	if _, err := srv2.Write(message); err != nil {
		t.Fatal(err)
	}

	recv = make([]byte, 1024)
	n, err = srv.Read(recv)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(message, recv[:n]) {
		t.Errorf("messages missmatch: %s != %s", message, recv[:n])
	}
}
