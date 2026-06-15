package exporter

import (
	"crypto/tls"
	"net"
	"os"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

func TestCreateClientTLSConfig(t *testing.T) {
	for _, test := range []struct {
		name          string
		options       Options
		expectSuccess bool
	}{
		// positive tests
		{"no_options", Options{}, true},
		{"skip_verificaton", Options{
			SkipTLSVerification: true,
		}, true},
		{"load_client_keypair", Options{
			ClientCertFile: "../contrib/tls/redis.crt",
			ClientKeyFile:  "../contrib/tls/redis.key",
		}, true},
		{"load_ca_cert", Options{
			CaCertFile: "../contrib/tls/ca.crt",
		}, true},
		{"load_system_certs", Options{}, true},

		// negative tests
		{"nonexisting_client_files", Options{
			ClientCertFile: "/nonexisting/file",
			ClientKeyFile:  "/nonexisting/file",
		}, false},
		{"nonexisting_ca_file", Options{
			CaCertFile: "/nonexisting/file",
		}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			e := getTestExporterWithOptions(t, test.options)

			_, err := e.CreateClientTLSConfig()
			if test.expectSuccess && err != nil {
				t.Errorf("Expected success for test: %s, got err: %s", test.name, err)
				return
			}
		})
	}
}

func TestValkeyTLSScheme(t *testing.T) {
	for _, host := range []string{
		os.Getenv("TEST_REDIS7_TLS_URI"),
		os.Getenv("TEST_VALKEY8_TLS_URI"),
	} {
		if host == "" {
			t.Skip("Skipping test, environment variable for TLS URI not set")
			continue
		}
		t.Run(host, func(t *testing.T) {
			e, _ := NewRedisExporter(
				host,
				Options{
					SkipTLSVerification: true,
					ClientCertFile:      "../contrib/tls/redis.crt",
					ClientKeyFile:       "../contrib/tls/redis.key",
				},
			)
			c, err := e.connectToRedis()
			if err != nil {
				t.Fatalf("connectToRedis() err: %s", err)
			}

			if _, err := c.Do("PING", ""); err != nil {
				t.Errorf("PING err: %s", err)
			}

			c.Close()

			chM := make(chan prometheus.Metric)
			go func() {
				e.Collect(chM)
				close(chM)
			}()

			tsts := []struct {
				in    string
				found bool
			}{
				{in: "db_keys"},
				{in: "commands_total"},
				{in: "total_connections_received"},
				{in: "used_memory"},
			}
			for m := range chM {
				desc := m.Desc().String()
				for i := range tsts {
					if strings.Contains(desc, tsts[i].in) {
						tsts[i].found = true
					}
				}
			}
		})
	}
}

func TestCreateServerTLSConfig(t *testing.T) {
	e := getTestExporter(t)

	// positive tests
	_, err := e.CreateServerTLSConfig("../contrib/tls/redis.crt", "../contrib/tls/redis.key", "", "TLS1.1")
	if err != nil {
		t.Errorf("CreateServerTLSConfig() err: %s", err)
	}
	_, err = e.CreateServerTLSConfig("../contrib/tls/redis.crt", "../contrib/tls/redis.key", "../contrib/tls/ca.crt", "TLS1.0")
	if err != nil {
		t.Errorf("CreateServerTLSConfig() err: %s", err)
	}

	// negative tests
	_, err = e.CreateServerTLSConfig("/nonexisting/file", "/nonexisting/file", "", "TLS1.1")
	if err == nil {
		t.Errorf("Expected CreateServerTLSConfig() to fail")
	}
	_, err = e.CreateServerTLSConfig("/nonexisting/file", "/nonexisting/file", "/nonexisting/file", "TLS1.2")
	if err == nil {
		t.Errorf("Expected CreateServerTLSConfig() to fail")
	}
	_, err = e.CreateServerTLSConfig("../contrib/tls/redis.crt", "../contrib/tls/redis.key", "/nonexisting/file", "TLS1.3")
	if err == nil {
		t.Errorf("Expected CreateServerTLSConfig() to fail")
	}
	_, err = e.CreateServerTLSConfig("../contrib/tls/redis.crt", "../contrib/tls/redis.key", "../contrib/tls/ca.crt", "TLSX")
	if err == nil {
		t.Errorf("Expected CreateServerTLSConfig() to fail")
	}
}

func TestGetServerCertificateFunc(t *testing.T) {
	// positive test
	_, err := GetServerCertificateFunc("../contrib/tls/ca.crt", "../contrib/tls/ca.key")(nil)
	if err != nil {
		t.Errorf("GetServerCertificateFunc() err: %s", err)
	}

	// negative test
	_, err = GetServerCertificateFunc("/nonexisting/file", "/nonexisting/file")(nil)
	if err == nil {
		t.Errorf("Expected GetServerCertificateFunc() to fail")
	}
}

func TestGetConfigForClientFunc(t *testing.T) {
	// positive test
	_, err := GetConfigForClientFunc("../contrib/tls/redis.crt", "../contrib/tls/redis.key", "../contrib/tls/ca.crt")(nil)
	if err != nil {
		t.Errorf("GetConfigForClientFunc() err: %s", err)
	}

	// negative test
	_, err = GetConfigForClientFunc("/nonexisting/file", "/nonexisting/file", "/nonexisting/file")(nil)
	if err == nil {
		t.Errorf("Expected GetConfigForClientFunc() to fail")
	}

	cert, err := tls.LoadX509KeyPair("../contrib/tls/redis.crt", "../contrib/tls/redis.key")
	if err != nil {
		t.Fatalf("LoadX509KeyPair() err: %s", err)
	}

	tlsConfigSrv := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfigSrv)
	if err != nil {
		t.Fatalf("tls.Listen() err: %s", err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				c.(*tls.Conn).Handshake() //nolint:errcheck
				c.Close()
			}(conn)
		}
	}()

	serverAddr := ln.Addr().String()
	certPath := "../contrib/tls/ca.crt"

	t.Run("no-config", func(t *testing.T) {
		e := &Exporter{
			options: Options{
				TlsServerName: "",
			},
		}
		tlsConfig, err := e.CreateClientTLSConfig()
		if err != nil {
			t.Fatalf("CreateClientTLSConfig() err: %s", err)
		}
		if tlsConfig.ServerName != "" {
			t.Errorf("expected empty ServerName, got %q", tlsConfig.ServerName)
		}

		// without verification and no CA, this will fail if we don't skip verification
		if _, err = tls.Dial("tcp", serverAddr, tlsConfig); err == nil {
			t.Errorf("expected tls.Dial() to fail")
		}
	})

	t.Run("localhost-should-pass", func(t *testing.T) {
		e := &Exporter{
			options: Options{
				TlsServerName: "localhost",
				CaCertFile:    certPath,
			},
		}
		tlsConfig, err := e.CreateClientTLSConfig()
		if err != nil {
			t.Fatalf("CreateClientTLSConfig() err: %s", err)
		}
		if tlsConfig.ServerName != "localhost" {
			t.Errorf("expected ServerName %q, got %q", "localhost", tlsConfig.ServerName)
		}

		conn, err := tls.Dial("tcp", serverAddr, tlsConfig)
		if err != nil {
			t.Fatalf("tls.Dial() err: %s", err)
		}
		conn.Close()
	})

	t.Run("127.0.0.1-should-fail", func(t *testing.T) {
		e := &Exporter{
			options: Options{
				TlsServerName: "127.0.0.1",
				CaCertFile:    certPath,
			},
		}
		tlsConfig, err := e.CreateClientTLSConfig()
		if err != nil {
			t.Fatalf("CreateClientTLSConfig() err: %s", err)
		}
		if tlsConfig.ServerName != "127.0.0.1" {
			t.Errorf("expected ServerName %q, got %q", "127.0.0.1", tlsConfig.ServerName)
		}

		_, err = tls.Dial("tcp", serverAddr, tlsConfig)
		if err == nil {
			t.Fatalf("expected tls.Dial() to fail")
		}
		if want := "cannot validate certificate for 127.0.0.1 because it doesn't contain any IP SANs"; !strings.Contains(err.Error(), want) {
			t.Errorf("expected err to contain %q, got: %s", want, err)
		}
	})
}
