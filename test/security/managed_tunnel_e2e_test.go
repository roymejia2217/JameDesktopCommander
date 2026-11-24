//go:build linux

// Non-release acceptance using the pinned upstream tunnel-client test support.
// Run only on a disposable hosted Linux runner with the actual candidate installed.
package managedtunnel_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
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

func rpcCommand(id, payload string) mocktunnelservice.CommandResponse {
	return mocktunnelservice.CommandResponse{
		Command:           mocktunnelservice.NewCommand(id, json.RawMessage(payload), nil),
		ExpectedResponses: []mocktunnelservice.ExpectedResponse{{RequestID: id}},
	}
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
	plane := mocktunnelservice.NewMockTunnelService(
		mocktunnelservice.WithAPIKey(key),
		mocktunnelservice.WithTunnelID(tunnelID),
		mocktunnelservice.WithInitializationPhaseCommandsWithoutSessionHeaders(),
		mocktunnelservice.WithCommandResponses(
			rpcCommand("jdc-list", `{"jsonrpc":"2.0","id":"list","method":"tools/list"}`),
			rpcCommand("jdc-deny", fmt.Sprintf(`{"jsonrpc":"2.0","id":"deny","method":"tools/call","params":{"name":"read_file","arguments":{"path":%q}}}`, sentinel)),
		),
	)
	plane.Start(t)
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
		t.Fatal("official tunnel did not complete the MCP scenario")
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

	seen := map[string]bool{}
	for _, response := range plane.ReceivedResponses(mocktunnelservice.ResponseMatchMatched) {
		if response.RequestID != "jdc-list" && response.RequestID != "jdc-deny" {
			continue
		}
		if seen[response.RequestID] || response.ResponseCode != http.StatusOK ||
			response.ResponseType != string(wiretypes.ResponsePayloadJSONRPC) {
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
