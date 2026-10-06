package vaultwarden

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// tlsServer ist ein Ersatz für Vaultwarden mit einem Zertifikat einer CA, die das System nicht kennt,
// wie bei einem Server hinter einer internen CA. Geliefert werden der Server und eine PEM-Datei mit
// seinem Zertifikat.
func tlsServer(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(srv.Close)
	file := filepath.Join(t.TempDir(), "ca.pem")
	data := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(file, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return srv, file
}

func TestHTTPClientRejectsAnUnknownCAUnlessItIsConfigured(t *testing.T) {
	srv, caFile := tlsServer(t)

	plain, err := HTTPClient("", 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if resp, err := plain.Get(srv.URL); err == nil {
		_ = resp.Body.Close()
		t.Fatal("a certificate from an unknown CA must be rejected")
	} else if err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("a certificate from an unknown CA must be rejected: %v", err)
	}

	trusting, err := HTTPClient(caFile, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := trusting.Get(srv.URL)
	if err != nil {
		t.Fatalf("the configured CA must be trusted: %v", err)
	}
	_ = resp.Body.Close()
}

// ownCertServer ist ein TLS-Server mit frisch erzeugtem Zertifikat. Anders als bei tlsServer, denn
// httptest gibt jedem Server dasselbe eingebaute Zertifikat.
func ownCertServer(t *testing.T) *httptest.Server {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "other"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func TestHTTPClientDoesNotSkipVerificationForOtherServers(t *testing.T) {
	_, caFile := tlsServer(t)
	other := ownCertServer(t) // ein anderes Zertifikat, das die konfigurierte CA-Datei nicht abdeckt
	c, err := HTTPClient(caFile, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if resp, err := c.Get(other.URL); err == nil {
		_ = resp.Body.Close()
		t.Fatal("trusting one CA must not turn verification off")
	}
}

func TestHTTPClientReportsBadCAFiles(t *testing.T) {
	if _, err := HTTPClient(filepath.Join(t.TempDir(), "missing.pem"), time.Second); err == nil || !strings.Contains(err.Error(), "VW_CA_FILE") {
		t.Fatalf("missing file: %v", err)
	}
	notPEM := filepath.Join(t.TempDir(), "x.pem")
	_ = os.WriteFile(notPEM, []byte("this is not a certificate"), 0o600)
	if _, err := HTTPClient(notPEM, time.Second); err == nil || !strings.Contains(err.Error(), "no PEM certificate") {
		t.Fatalf("garbage file: %v", err)
	}
}
