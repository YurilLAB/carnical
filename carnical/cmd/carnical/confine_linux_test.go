//go:build linux && (amd64 || arm64)

package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/YurilLAB/coraza/carnical/audit"
	"github.com/YurilLAB/coraza/carnical/audit/host"
)

// The real binary, confined, serving real requests: everything the proxy does in a day must still work inside the
// confinement, and the process must show the restrictions the kernel reports for every one of its threads.
func TestTheConfinedProxyStillDoesItsJob(t *testing.T) {
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

	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		fmt.Fprint(w, "reached the application")
	}))
	defer app.Close()
	appPort := app.Listener.Addr().(*net.TCPAddr).Port

	for _, confined := range []bool{true, false} {
		name := "confined"
		if !confined {
			name = "control, not confined"
		}
		t.Run(name, func(t *testing.T) {
			free, _ := net.Listen("tcp", "127.0.0.1:0")
			addr := free.Addr().String()
			free.Close()
			uploads, err := os.MkdirTemp("", "uploads") // a plain name: the setting only accepts a plain path
			if err != nil {
				t.Fatal(err)
			}
			defer os.RemoveAll(uploads)
			args := []string{"-listen", addr, "-upstream", app.URL, "-origin-allow", "127.0.0.0/8", "-mode", "block", "-upload-dir", uploads, "-max-conns-per-ip", "-1"}
			if confined {
				args = append(args, "-confine", "-confine-connect", fmt.Sprint(appPort))
			}
			var logs bytes.Buffer
			cmd := exec.Command(bin, args...)
			cmd.Stdout, cmd.Stderr = &logs, &logs
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			exited := make(chan error, 1)
			go func() { exited <- cmd.Wait() }()
			defer func() {
				cmd.Process.Signal(syscall.SIGTERM)
				select {
				case err := <-exited:
					if err != nil {
						t.Errorf("the proxy did not shut down cleanly: %v\n%s", err, logs.String())
					}
				case <-time.After(15 * time.Second):
					cmd.Process.Kill()
					t.Error("the proxy did not shut down")
				}
			}()

			base := "http://" + addr
			client := &http.Client{Timeout: 10 * time.Second}
			deadline := time.Now().Add(20 * time.Second)
			for {
				resp, err := client.Get(base + "/")
				if err == nil {
					resp.Body.Close()
					break
				}
				select {
				case err := <-exited:
					t.Fatalf("the proxy exited early: %v\n%s", err, logs.String())
				default:
				}
				if time.Now().After(deadline) {
					t.Fatalf("the proxy never came up\n%s", logs.String())
				}
				time.Sleep(100 * time.Millisecond)
			}

			get := func(path string) (int, string) {
				resp, err := client.Get(base + path)
				if err != nil {
					t.Fatalf("GET %s: %v\n%s", path, err, logs.String())
				}
				defer resp.Body.Close()
				b, _ := io.ReadAll(resp.Body)
				return resp.StatusCode, string(b)
			}
			if status, body := get("/page"); status != 200 || !strings.Contains(body, "reached the application") {
				t.Fatalf("an ordinary request: %d %q", status, body)
			}
			if status, _ := get("/x?q=%3Cscript%3Ealert(1)%3C/script%3E"); status != 403 {
				t.Fatalf("an attack: %d, want 403", status)
			}
			if status, _ := get("/a%2fb"); status != 400 {
				t.Fatalf("a path that needs interpreting: %d, want 400", status)
			}

			// An upload: the engine writes the file part into the upload directory while the request runs.
			var body bytes.Buffer
			mw := multipart.NewWriter(&body)
			part, _ := mw.CreateFormFile("file", "photo.jpg")
			part.Write(bytes.Repeat([]byte("an ordinary picture "), 2000))
			mw.Close()
			resp, err := client.Post(base+"/upload", mw.FormDataContentType(), &body)
			if err != nil {
				t.Fatalf("upload: %v\n%s", err, logs.String())
			}
			resp.Body.Close()
			if resp.StatusCode != 200 {
				t.Fatalf("an upload: %d\n%s", resp.StatusCode, logs.String())
			}
			if left, _ := os.ReadDir(uploads); len(left) != 0 {
				t.Fatalf("%d upload file(s) left behind", len(left))
			}

			// What the kernel says about every thread of the process.
			tasks, _ := filepath.Glob(fmt.Sprintf("/proc/%d/task/*/status", cmd.Process.Pid))
			if len(tasks) < 3 {
				t.Fatalf("only %d threads to look at", len(tasks))
			}
			for _, status := range tasks {
				data, err := os.ReadFile(status)
				if err != nil {
					continue
				}
				text := string(data)
				wantFilter, wantNNP := "Seccomp:\t0", "NoNewPrivs:\t0"
				if confined {
					wantFilter, wantNNP = "Seccomp:\t2", "NoNewPrivs:\t1"
				}
				if !strings.Contains(text, wantFilter) || !strings.Contains(text, wantNNP) {
					t.Fatalf("%s: want %q and %q:\n%s", status, wantFilter, wantNNP, text)
				}
			}
			// The host audit's own view of the same process: it must pass for the confined proxy and fail for the control, or
			// it is not telling them apart.
			me, err := user.Current()
			if err != nil {
				t.Fatal(err)
			}
			res := audit.Run(context.Background(), []audit.Check{host.Confined(host.OS{}, host.EdgeSpec{Exe: bin, User: me.Username})}, 10*time.Second).Results[0]
			switch {
			case confined && os.Geteuid() == 0 && res.Status != audit.Pass:
				t.Fatalf("the audit does not see the confined proxy as confined: %+v", res)
			case confined && os.Geteuid() != 0 && res.Status != audit.Skip:
				// A process that is not dumpable hides its program from other processes of the same user, which is the
				// protection working: only root (or CAP_SYS_PTRACE) can see it, so that is who the host audit runs as.
				t.Fatalf("an unprivileged observer could see a non-dumpable process's program: %+v", res)
			}
			if !confined && res.Status != audit.Fail {
				t.Fatalf("the audit passed a proxy that is not confined: %+v", res)
			}
			if confined && !strings.Contains(logs.String(), `"msg":"confined"`) {
				t.Fatalf("the proxy did not say it was confined:\n%s", logs.String())
			}
		})
	}
}
