//go:build linux

// Non-release acceptance using the pinned upstream tunnel-client test support.
// Run only on a disposable hosted Linux runner with the actual candidate installed.
package managedtunnel_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openai/tunnel-client/pkg/controlplane/wiretypes"
	"github.com/openai/tunnel-client/testsupport/mocktunnelservice"
)

const (
	unit         = "jdc-managed-tunnel.service"
	account      = "jdc-managed-tunnel"
	unitPath     = "/etc/systemd/system/" + unit
	dropinDir    = unitPath + ".d"
	profileRoot  = "/etc/jdc/managed-tunnel"
	credential   = profileRoot + "/control-plane-api-key"
	sentinel     = profileRoot + "/inside.txt"
	clientBinary = "/opt/jame-desktop-commander/tools/tunnel-client/tunnel-client"
	healthSocket = "/run/" + account + "/health.sock"
)

func command(t *testing.T, executable string, args ...string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, executable, args...).Output()
	return strings.TrimSpace(string(out)), err
}

func must(t *testing.T, executable string, args ...string) string {
	t.Helper()
	out, err := command(t, executable, args...)
	if err != nil {
		t.Fatalf("%s failed: %v", executable, err)
	}
	return out
}

func root(t *testing.T, args ...string) string {
	t.Helper()
	return must(t, "sudo", append([]string{"-n"}, args...)...)
}

func cleanupRoot(t *testing.T, args ...string) {
	t.Helper()
	if _, err := command(t, "sudo", append([]string{"-n"}, args...)...); err != nil {
		t.Errorf("cleanup %s failed: %v", args[0], err)
	}
}

func absentAccount(t *testing.T, database string) {
	t.Helper()
	_, err := command(t, "getent", database, account)
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 2 {
		t.Fatalf("refusing pre-existing or unverifiable %s account", database)
	}
}

func createDir(t *testing.T, path string) {
	t.Helper()
	root(t, "install", "-d", "-o", "root", "-g", "root", "-m", "0755", path)
	t.Cleanup(func() { cleanupRoot(t, "rmdir", path) })
}

func installFile(t *testing.T, src, dst, mode string) {
	t.Helper()
	root(t, "install", "-o", "root", "-g", "root", "-m", mode, src, dst)
	t.Cleanup(func() { cleanupRoot(t, "rm", "-f", "--", dst) })
}

func fixtureFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal("cannot write disposable test fixture")
	}
	return path
}

func rpcCommand(id, payload string) json.RawMessage {
	return mocktunnelservice.NewCommand(id, json.RawMessage(payload), http.Header{
		"Accept":       {"application/json, text/event-stream"},
		"Content-Type": {"application/json"},
	})
}

func TestManagedOfficialTunnelDeniesWithoutBroker(t *testing.T) {
	if os.Getenv("JDC_MANAGED_TUNNEL_ACCEPTANCE") != "1" ||
		os.Getenv("GITHUB_ACTIONS") != "true" ||
		os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" ||
		os.Getenv("RUNNER_OS") != "Linux" ||
		os.Getenv("GITHUB_REPOSITORY") != "roymejia2217/JameDesktopCommander" ||
		os.Geteuid() == 0 {
		t.Fatal("requires explicitly authorized disposable hosted Linux runner")
	}
	repo := os.Getenv("JDC_ACCEPTANCE_SOURCE_ROOT")
	if !filepath.IsAbs(repo) {
		t.Fatal("missing absolute acceptance source root")
	}
	for _, path := range []string{"/etc/jdc", unitPath, dropinDir,
		"/usr/lib/systemd/system/" + unit, "/lib/systemd/system/" + unit,
		"/var/lib/" + account, "/run/" + account} {
		root(t, "test", "!", "-e", path)
		root(t, "test", "!", "-L", path)
	}
	absentAccount(t, "passwd")
	absentAccount(t, "group")
	root(t, "test", "-x", clientBinary)
	root(t, "test", "-x", "/opt/jame-desktop-commander/runtime/node")
	root(t, "test", "-f", "/opt/jame-desktop-commander/dist/index.js")
	if !strings.HasPrefix(must(t, clientBinary, "--version"), "0.0.19") {
		t.Fatal("unexpected installed tunnel version")
	}

	const key = "jdc-disposable-test-key"
	const tunnelID = "tunnel_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	plane := newManagedPlane(t, key, tunnelID, []json.RawMessage{
		rpcCommand("jdc-init", `{"jsonrpc":"2.0","id":"init","method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"jdc-acceptance","version":"1"}}}`),
		rpcCommand("jdc-ack", `{"jsonrpc":"2.0","method":"notifications/initialized"}`),
		rpcCommand("jdc-list", `{"jsonrpc":"2.0","id":"list","method":"tools/list"}`),
		rpcCommand("jdc-deny", fmt.Sprintf(`{"jsonrpc":"2.0","id":"deny","method":"tools/call","params":{"name":"read_file","arguments":{"path":%q}}}`, sentinel)),
	})
	if plane.BaseURL().Hostname() != "127.0.0.1" {
		t.Fatal("test provider must listen on IPv4 loopback")
	}
	dir := t.TempDir()
	profile := fmt.Sprintf("config_version: 1\ncontrol_plane:\n  base_url: %q\n  tunnel_id: %q\n  api_key: file:/run/credentials/%s/control-plane-api-key\ncloudflared:\n  managed: false\nadmin_ui:\n  open_browser: false\n", plane.BaseURL().String(), tunnelID, unit)
	createDir(t, "/etc/jdc")
	createDir(t, profileRoot)
	createDir(t, profileRoot+"/profiles")
	installFile(t, fixtureFile(t, dir, "managed.yaml", profile), profileRoot+"/profiles/managed.yaml", "0644")
	installFile(t, fixtureFile(t, dir, "key", key), credential, "0600")
	installFile(t, fixtureFile(t, dir, "inside.txt", "JDC_DISPOSABLE_SENTINEL"), sentinel, "0644")
	if _, err := os.ReadFile(credential); !errors.Is(err, os.ErrPermission) {
		t.Fatal("runner identity must not be able to read protected credential")
	}

	root(t, "systemd-sysusers", filepath.Join(repo, "packaging/experimental/linux/sysusers.d/jdc-managed-tunnel.conf"))
	t.Cleanup(func() {
		cleanupRoot(t, "userdel", account)
		if _, err := command(t, "getent", "group", account); err == nil {
			cleanupRoot(t, "groupdel", account)
		}
	})
	t.Cleanup(func() { cleanupRoot(t, "systemctl", "daemon-reload") })
	installFile(t, filepath.Join(repo, "packaging/experimental/linux/systemd/jdc-managed-tunnel.service"), unitPath, "0644")
	createDir(t, dropinDir)
	installFile(t, fixtureFile(t, dir, "test.conf",
		"[Service]\nIPAddressDeny=any\nIPAddressAllow=localhost\nEnvironment=DESKTOP_COMMANDER_DISABLE_TELEMETRY=1\n"),
		dropinDir+"/test.conf", "0644")
	root(t, "systemctl", "daemon-reload")
	t.Cleanup(func() {
		cleanupRoot(t, "systemctl", "stop", unit)
		cleanupRoot(t, "systemctl", "clean", "--what=state,runtime", unit)
	})
	root(t, "systemctl", "start", unit)

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	if err := plane.WaitUntilIdle(ctx); err != nil {
		t.Fatalf("official tunnel did not complete the MCP scenario: %v", err)
	}
	root(t, "test", "-S", healthSocket)
	conn, err := net.DialTimeout("unix", healthSocket, 2*time.Second)
	if conn != nil {
		_ = conn.Close()
	}
	if !errors.Is(err, os.ErrPermission) {
		t.Fatal("unprivileged runner must be denied access to the private health socket")
	}
	pid, err := strconv.Atoi(root(t, "systemctl", "show", "--property=MainPID", "--value", unit))
	if err != nil || pid <= 1 {
		t.Fatal("managed tunnel service has no live main process")
	}
	proc := fmt.Sprintf("/proc/%d", pid)
	if root(t, "readlink", "-f", proc+"/exe") != clientBinary {
		t.Fatal("managed service did not execute the installed official client")
	}
	fields := strings.Split(must(t, "getent", "passwd", account), ":")
	if len(fields) < 4 || fields[2] == strconv.Itoa(os.Geteuid()) || fields[2] == "0" {
		t.Fatal("managed identity must differ from runner and root")
	}
	status := root(t, "cat", proc+"/status")
	if !strings.Contains(status, "Uid:\t"+fields[2]+"\t"+fields[2]+"\t"+fields[2]+"\t"+fields[2]+"\n") {
		t.Fatal("actual tunnel process does not have the dedicated UID")
	}

	// End delivery before freezing the complete response evidence.
	root(t, "systemctl", "stop", unit)
	seen := map[string]bool{}
	for _, response := range plane.terminalResponses(t) {
		if response.RequestID != "jdc-list" && response.RequestID != "jdc-deny" {
			continue
		}
		if seen[response.RequestID] || response.ResponseCode != http.StatusOK ||
			response.ResponseType != wiretypes.ResponsePayloadJSONRPC {
			t.Fatal("invalid or duplicate MCP response")
		}
		seen[response.RequestID] = true
		var envelope struct {
			ID     string `json:"id"`
			Result struct {
				Tools []struct {
					Name string `json:"name"`
				} `json:"tools"`
				IsError bool                          `json:"isError"`
				Content []struct{ Type, Text string } `json:"content"`
			} `json:"result"`
		}
		if err := json.Unmarshal(response.JSONResponse, &envelope); err != nil {
			t.Fatal("invalid MCP response envelope")
		}
		if response.RequestID == "jdc-list" {
			found := false
			for _, tool := range envelope.Result.Tools {
				found = found || tool.Name == "read_file"
			}
			if envelope.ID != "list" || !found || envelope.Result.IsError {
				t.Fatal("real JDC did not advertise read_file")
			}
		} else {
			if envelope.ID != "deny" || !envelope.Result.IsError ||
				len(envelope.Result.Content) != 1 ||
				envelope.Result.Content[0].Type != "text" ||
				!strings.Contains(envelope.Result.Content[0].Text, "E_NATIVE_AUTHORITY_UNAVAILABLE") ||
				strings.Contains(envelope.Result.Content[0].Text, "JDC_DISPOSABLE_SENTINEL") {
				t.Fatal("native-required real MCP read did not deny before legacy disclosure")
			}
		}
	}
	if !seen["jdc-list"] || !seen["jdc-deny"] {
		t.Fatal("missing tool catalog or native denial")
	}
}

// managedPlane is a test-only HTTP control plane using the pinned upstream
// wire contract. Unlike the fixed-count upstream mock, it treats notifications
// as nonterminal frames and advances only on a correlated terminal response.
type managedPlane struct {
	key, prefix   string
	commands      []json.RawMessage
	server        *httptest.Server
	mu            sync.Mutex
	next          int
	delivered     bool
	notifications int
	responses     []wiretypes.TunnelResponsePayload
	done          chan struct{}
	err           error
}

func newManagedPlane(t *testing.T, key, tunnelID string, commands []json.RawMessage) *managedPlane {
	t.Helper()
	p := &managedPlane{key: key, prefix: "/v1/tunnels/" + tunnelID, commands: commands, done: make(chan struct{})}
	p.server = httptest.NewServer(p)
	t.Cleanup(p.server.Close)
	return p
}

func (p *managedPlane) BaseURL() *url.URL {
	u, _ := url.Parse(p.server.URL)
	return u
}

func (p *managedPlane) WaitUntilIdle(ctx context.Context) error {
	select {
	case <-p.done:
		p.mu.Lock()
		defer p.mu.Unlock()
		return p.err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (p *managedPlane) terminalResponses(t *testing.T) []wiretypes.TunnelResponsePayload {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.err != nil || p.next != len(p.commands) || len(p.responses) != len(p.commands) {
		t.Fatalf("incomplete or invalid terminal sequence: %v", p.err)
	}
	return append([]wiretypes.TunnelResponsePayload(nil), p.responses...)
}

// Called under mu. Unexpected frames are a test failure, not silently dropped.
func (p *managedPlane) reject(w http.ResponseWriter, reason string) {
	if p.err == nil {
		p.err = errors.New(reason)
		if p.next < len(p.commands) {
			close(p.done)
		}
	}
	http.Error(w, reason, http.StatusBadRequest)
}

func (p *managedPlane) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != p.prefix+"/poll" && r.URL.Path != p.prefix+"/response" {
		http.NotFound(w, r)
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if r.Header.Get("Authorization") != "Bearer "+p.key || r.Header.Get("Accept") != "application/json" {
		p.reject(w, "invalid control-plane authentication or accept header")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if r.URL.Path == p.prefix+"/poll" && r.Method == http.MethodGet {
		commands := []json.RawMessage{}
		if p.err == nil && !p.delivered && p.next < len(p.commands) {
			commands = append(commands, p.commands[p.next])
			p.delivered = true
		}
		if err := json.NewEncoder(w).Encode(wiretypes.PolledCommandEnvelope{Commands: commands}); err != nil {
			p.reject(w, "cannot encode command envelope")
		}
		return
	}
	if r.URL.Path != p.prefix+"/response" || r.Method != http.MethodPost ||
		r.Header.Get("Content-Type") != "application/json" || !p.delivered || p.next >= len(p.commands) || p.err != nil {
		p.reject(w, "unexpected response request")
		return
	}
	var frame wiretypes.TunnelResponsePayload
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2<<20))
	if err := decoder.Decode(&frame); err != nil {
		p.reject(w, "invalid response envelope")
		return
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		p.reject(w, "trailing response data")
		return
	}
	var command wiretypes.RawJSONRPCPolledCommand
	if err := json.Unmarshal(p.commands[p.next], &command); err != nil ||
		frame.RequestID != command.RequestID || r.Header.Get("X-Tunnel-Shard-Token") != command.ShardToken ||
		frame.ResponseCode < 200 || frame.ResponseCode >= 300 {
		p.reject(w, "uncorrelated or unsuccessful MCP response")
		return
	}
	var request, response struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Method  string          `json:"method"`
		Result  json.RawMessage `json:"result"`
		Error   json.RawMessage `json:"error"`
		Params  json.RawMessage `json:"params"`
	}
	if err := json.Unmarshal(command.JSONRPC, &request); err != nil {
		p.reject(w, "invalid fixture command")
		return
	}
	if frame.ResponseType == wiretypes.ResponsePayloadJSONRPCNotify {
		if err := json.Unmarshal(frame.JSONResponse, &response); err != nil ||
			response.JSONRPC != "2.0" || !strings.HasPrefix(response.Method, "notifications/") ||
			len(response.ID) != 0 || len(response.Result) != 0 || len(response.Error) != 0 ||
			p.notifications >= 256 {
			p.reject(w, "invalid or excessive nonterminal notification")
			return
		}
		p.notifications++
	} else {
		if len(request.ID) == 0 {
			if frame.ResponseType != wiretypes.ResponsePayloadNotifyAck || len(frame.JSONResponse) != 0 {
				p.reject(w, "invalid notification acknowledgement")
				return
			}
		} else {
			if frame.ResponseType != wiretypes.ResponsePayloadJSONRPC ||
				json.Unmarshal(frame.JSONResponse, &response) != nil || response.JSONRPC != "2.0" ||
				!bytes.Equal(response.ID, request.ID) || len(response.Result) == 0 ||
				len(response.Error) != 0 || response.Method != "" {
				p.reject(w, "invalid terminal JSON-RPC result")
				return
			}
			if request.Method == "initialize" {
				var result struct {
					ProtocolVersion string `json:"protocolVersion"`
					ServerInfo      struct {
						Name    string `json:"name"`
						Version string `json:"version"`
					} `json:"serverInfo"`
				}
				if json.Unmarshal(response.Result, &result) != nil || result.ProtocolVersion == "" ||
					result.ServerInfo.Name == "" || result.ServerInfo.Version == "" {
					p.reject(w, "invalid initialize identity")
					return
				}
			}
		}
		p.responses = append(p.responses, frame)
		p.delivered = false
		p.next++
		p.notifications = 0
		if p.next == len(p.commands) {
			close(p.done)
		}
	}
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

func TestManagedPlaneSeparatesNotificationsFromTerminalResponses(t *testing.T) {
	const key, id = "test-key", "test-tunnel"
	p := newManagedPlane(t, key, id, []json.RawMessage{
		rpcCommand("first", `{"jsonrpc":"2.0","id":"rpc-first","method":"tools/list"}`),
		rpcCommand("second", `{"jsonrpc":"2.0","method":"notifications/initialized"}`),
	})
	exchange := func(method, suffix, shard, body string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, p.prefix+suffix, strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+key)
		r.Header.Set("Accept", "application/json")
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-Tunnel-Shard-Token", shard)
		w := httptest.NewRecorder()
		p.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("unexpected fixture HTTP status %d: %s", w.Code, w.Body.String())
		}
		return w
	}
	poll := func(want string) {
		t.Helper()
		var envelope wiretypes.PolledCommandEnvelope
		if err := json.Unmarshal(exchange(http.MethodGet, "/poll", "", "").Body.Bytes(), &envelope); err != nil {
			t.Fatal(err)
		}
		if want == "" {
			if len(envelope.Commands) != 0 {
				t.Fatal("unexpected command before terminal response")
			}
			return
		}
		var command wiretypes.RawJSONRPCPolledCommand
		if len(envelope.Commands) != 1 || json.Unmarshal(envelope.Commands[0], &command) != nil || command.RequestID != want {
			t.Fatalf("missing or incorrect command %s", want)
		}
	}
	poll("first")
	for range 3 {
		exchange(http.MethodPost, "/response", "first", `{"request_id":"first","resp_code":200,"resp_type":"jsonrpc_notify","resp_json":{"jsonrpc":"2.0","method":"notifications/message","params":{"level":"info","data":"test"}}}`)
		poll("")
	}
	exchange(http.MethodPost, "/response", "first", `{"request_id":"first","resp_code":200,"resp_type":"jsonrpc_response","resp_json":{"jsonrpc":"2.0","id":"rpc-first","result":{"tools":[]}}}`)
	poll("second")
	exchange(http.MethodPost, "/response", "second", `{"request_id":"second","resp_code":202,"resp_type":"notify_ack"}`)
	poll("")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := p.WaitUntilIdle(ctx); err != nil {
		t.Fatal(err)
	}
	if len(p.terminalResponses(t)) != 2 {
		t.Fatal("notifications must not count as terminal results")
	}
}

func TestManagedPlaneRejectsInvalidResponseCorrelation(t *testing.T) {
	for _, tc := range []struct{ name, shard, body string }{
		{"wrong request", "first", `{"request_id":"wrong","resp_code":200,"resp_type":"jsonrpc_notify","resp_json":{"jsonrpc":"2.0","method":"notifications/message"}}`},
		{"wrong shard", "wrong", `{"request_id":"first","resp_code":200,"resp_type":"jsonrpc_notify","resp_json":{"jsonrpc":"2.0","method":"notifications/message"}}`},
		{"wrong rpc id", "first", `{"request_id":"first","resp_code":200,"resp_type":"jsonrpc_response","resp_json":{"jsonrpc":"2.0","id":"wrong","result":{}}}`},
		{"notification with id", "first", `{"request_id":"first","resp_code":200,"resp_type":"jsonrpc_notify","resp_json":{"jsonrpc":"2.0","id":"wrong","method":"notifications/message"}}`},
		{"terminal error", "first", `{"request_id":"first","resp_code":200,"resp_type":"jsonrpc_response","resp_json":{"jsonrpc":"2.0","id":"rpc-first","error":{"code":-32000,"message":"failure"}}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newManagedPlane(t, "test-key", "test-tunnel", []json.RawMessage{
				rpcCommand("first", `{"jsonrpc":"2.0","id":"rpc-first","method":"tools/list"}`),
			})
			request := func(method, suffix, body string) *httptest.ResponseRecorder {
				r := httptest.NewRequest(method, p.prefix+suffix, strings.NewReader(body))
				r.Header.Set("Authorization", "Bearer test-key")
				r.Header.Set("Accept", "application/json")
				r.Header.Set("Content-Type", "application/json")
				r.Header.Set("X-Tunnel-Shard-Token", tc.shard)
				w := httptest.NewRecorder()
				p.ServeHTTP(w, r)
				return w
			}
			if request(http.MethodGet, "/poll", "").Code != http.StatusOK {
				t.Fatal("poll failed")
			}
			if request(http.MethodPost, "/response", tc.body).Code != http.StatusBadRequest {
				t.Fatal("invalid response accepted")
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if err := p.WaitUntilIdle(ctx); err == nil || errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("expected specific terminal rejection, got %v", err)
			}
			if len(p.responses) != 0 || p.next != 0 {
				t.Fatal("invalid response advanced terminal sequence")
			}
		})
	}
}
