package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"os/signal"
	"time"

	"github.com/igolaizola/resumetls"
)

func main() {
	// Context signal
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	switch os.Args[1] {
	case "server":
		if err := runServer(ctx); err != nil {
			log.Fatalf("Failed to run server: %v", err)
		}
	case "client":
		if err := runClient(ctx); err != nil {
			log.Fatalf("Failed to run client: %v", err)
		}
	default:
		log.Fatalf("Invalid argument: %s", os.Args[1])
	}
}

func runClient(ctx context.Context) error {
	// Create a custom dialer
	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	// Establish a TCP connection
	tcpConn, err := dialer.DialContext(ctx, "tcp", "localhost:4433")
	if err != nil {
		return fmt.Errorf("couldn't dial server: %w", err)
	}
	defer tcpConn.Close()
	fmt.Println("Connected to server")

	cfg := &tls.Config{
		InsecureSkipVerify: true,
	}

	// Create a resumable TLS client
	conn, err := resumetls.Client(tcpConn, cfg, nil)
	if err != nil {
		return fmt.Errorf("couldn't create resumable tls client: %w", err)
	}
	if err := conn.Handshake(); err != nil {
		return fmt.Errorf("couldn't handshake: %w", err)
	}

	// Send a message
	if _, err := conn.Write([]byte("🍓 Strawberries 🍓\n")); err != nil {
		return fmt.Errorf("couldn't write message: %w", err)
	}

	// Resume the client
	state := conn.State()
	conn2, err := resumetls.Client(tcpConn, cfg, state)
	if err != nil {
		return fmt.Errorf("couldn't resume client: %w", err)
	}

	// Send a message
	if _, err := conn2.Write([]byte("🍌 Bananas 🍌\n")); err != nil {
		return fmt.Errorf("couldn't write message: %w", err)
	}

	log.Println("Messages sent successfully")

	if err := conn2.Close(); err != nil {
		return fmt.Errorf("couldn't close connection: %w", err)
	}
	return nil
}

func runServer(ctx context.Context) error {
	// Generate a dynamic certificate
	cert, err := generateCert()
	if err != nil {
		return fmt.Errorf("couldn't generate certificate: %w", err)
	}

	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	// Create a TCP listener
	listener, err := net.Listen("tcp", ":4433")
	if err != nil {
		return fmt.Errorf("couldn't create listener: %w", err)
	}
	defer listener.Close()
	fmt.Println("Server listening on :4433")

	go func() {
		<-ctx.Done()
		listener.Close()
	}()

	// Wait for first connection
	tcpConn, err := listener.Accept()
	if err != nil {
		return fmt.Errorf("couldn't accept connection: %w", err)
	}
	defer tcpConn.Close()

	// Create a resumable TLS server
	conn, err := resumetls.Server(tcpConn, cfg, nil)
	if err != nil {
		return fmt.Errorf("couldn't create resumable tls server: %w", err)
	}
	if err := conn.Handshake(); err != nil {
		return fmt.Errorf("couldn't handshake: %w", err)
	}

	// Send a message
	if _, err := conn.Write([]byte("🍓 Strawberries 🍓\n")); err != nil {
		return fmt.Errorf("couldn't write message: %w", err)
	}

	// Resume the server
	state := conn.State()
	conn2, err := resumetls.Server(tcpConn, cfg, state)
	if err != nil {
		return fmt.Errorf("couldn't resume server: %w", err)
	}

	// Send a message
	if _, err := conn2.Write([]byte("🍌 Bananas 🍌\n")); err != nil {
		return fmt.Errorf("couldn't write message: %w", err)
	}

	log.Println("Messages sent successfully")
	return nil
}

func generateCert() (tls.Certificate, error) {
	// Generate a new ECDSA private key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("couldn't generate private key: %w", err)
	}

	// Create a certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Corp"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	// Create the certificate
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("couldn't create certificate: %w", err)
	}

	// Encode the private key and certificate to PEM format
	privBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("couldn't marshal private key: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})

	// Load the certificate
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("couldn't load certificate: %w", err)
	}

	return cert, nil
}
