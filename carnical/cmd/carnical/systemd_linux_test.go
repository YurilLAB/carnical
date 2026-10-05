//go:build linux && (amd64 || arm64)

package main

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Socket activation: systemd opens port 443 and hands the proxy the open socket, so the proxy needs no privilege (no
// capability to bind a low port) and, once confined, cannot open a listening socket of its own.
func TestTheProxyServesOnASocketSystemdHandsOver(t *testing.T) {
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("no go command to build with")
	}
	bin := filepath.Join(t.TempDir(), "carnical")
	build := exec.Command(goBin, "build", "-o", bin, ".")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "reached the application") }))
	defer app.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	file, err := ln.(*net.TCPListener).File()
	if err != nil {
		t.Fatal(err)
	}
	args := []string{"-systemd-socket", "-upstream", app.URL, "-origin-allow", "127.0.0.0/8", "-max-conns-per-ip", "-1", "-confine", "-confine-connect", fmt.Sprint(app.Listener.Addr().(*net.TCPAddr).Port)}

	// sd_listen_fds(3): the socket is descriptor 3 and LISTEN_PID is the process's own id, which the shell sets by exec.
	var logs bytes.Buffer
	cmd := exec.Command("sh", append([]string{"-c", `export LISTEN_PID=$$ LISTEN_FDS=1; exec "$0" "$@"`, bin}, args...)...)
	cmd.ExtraFiles = []*os.File{file}
	cmd.Stdout, cmd.Stderr = &logs, &logs
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	file.Close()
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	defer func() {
		cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-exited:
		case <-time.After(15 * time.Second):
			cmd.Process.Kill()
		}
	}()

	client := &http.Client{Timeout: 10 * time.Second}
	deadline := time.Now().Add(20 * time.Second)
	for {
		resp, err := client.Get("http://" + ln.Addr().String() + "/page")
		if err == nil {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode != 200 || !strings.Contains(string(body), "reached the application") {
				t.Fatalf("status %d, body %q\n%s", resp.StatusCode, body, logs.String())
			}
			break
		}
		select {
		case err := <-exited:
			t.Fatalf("the proxy exited: %v\n%s", err, logs.String())
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("no answer: %v\n%s", err, logs.String())
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !strings.Contains(logs.String(), `"msg":"confined"`) {
		t.Fatalf("the proxy did not confine itself:\n%s", logs.String())
	}
	ln.Close()

	// Asked for a socket from systemd and not given one, it refuses to start rather than listening somewhere else.
	out, err := exec.Command(bin, "-systemd-socket", "-upstream", app.URL, "-origin-allow", "127.0.0.0/8").CombinedOutput()
	if err == nil || !strings.Contains(string(out), "did not pass exactly one socket") {
		t.Fatalf("started without a socket from systemd: %v\n%s", err, out)
	}
}
