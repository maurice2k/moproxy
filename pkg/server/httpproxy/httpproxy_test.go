package httpproxy_test

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"moproxy/pkg/config"
	"moproxy/pkg/server/httpproxy"
)

func TestConnectTunnelOutlivesNegotiationTimeout(t *testing.T) {
	const negotiationTimeout = 50 * time.Millisecond

	backend, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen on backend: %v", err)
	}
	t.Cleanup(func() { _ = backend.Close() })

	go func() {
		conn, acceptErr := backend.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		_, _ = io.Copy(conn, conn)
	}()

	configPath := filepath.Join(t.TempDir(), "moproxy.conf")
	configJSON := fmt.Sprintf(`{
		"access": {
			"clientRules": ["allow from all to all"],
			"proxyRules": ["allow from all to all"]
		},
		"timeout": {
			"tcp": {"connect": "1s", "negotiate": %q},
			"http": {"keepAlive": "1s"}
		}
	}`, negotiationTimeout.String())
	if err := os.WriteFile(configPath, []byte(configJSON), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	proxyConfig, err := config.LoadConfig(configPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	proxy := httpproxy.NewServer("127.0.0.1:0", "127.0.0.1", proxyConfig)
	if err := proxy.Listen(); err != nil {
		t.Fatalf("listen on proxy: %v", err)
	}
	t.Cleanup(func() { _ = proxy.Halt() })
	go func() { _ = proxy.Serve() }()

	client, err := net.Dial("tcp4", proxy.GetListenAddr().String())
	if err != nil {
		t.Fatalf("connect to proxy: %v", err)
	}
	defer client.Close()

	if _, err := fmt.Fprintf(client, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", backend.Addr(), backend.Addr()); err != nil {
		t.Fatalf("send CONNECT request: %v", err)
	}

	reader := bufio.NewReader(client)
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT status = %d, want %d", response.StatusCode, http.StatusOK)
	}

	time.Sleep(2 * negotiationTimeout)
	if err := client.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("set client deadline: %v", err)
	}

	const payload = "ping"
	if _, err := io.WriteString(client, payload); err != nil {
		t.Fatalf("write tunneled payload: %v", err)
	}
	buffer := make([]byte, len(payload))
	if _, err := io.ReadFull(reader, buffer); err != nil {
		t.Fatalf("read tunneled payload after negotiation timeout: %v", err)
	}
	if got := string(buffer); got != payload {
		t.Fatalf("tunneled payload = %q, want %q", got, payload)
	}
}
