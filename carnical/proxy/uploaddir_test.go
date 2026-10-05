package proxy

import (
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"testing"
	"time"
)

// While a request is being handled, where does the engine keep the file parts of an upload? The system's temporary
// directory is shared with every other program on the machine; the proxy is told to use a directory of its own.
func TestUploadsAreKeptInTheirOwnDirectoryWhileTheRequestRuns(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the system temporary directory is chosen differently here")
	}
	for _, own := range []bool{false, true} {
		name := "default"
		if own {
			name = "own directory"
		}
		t.Run(name, func(t *testing.T) {
			shared, mine := t.TempDir(), t.TempDir()
			t.Setenv("TMPDIR", shared)

			atApp, release := make(chan struct{}), make(chan struct{})
			app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				close(atApp)
				<-release // the engine still has the request open
				w.Write([]byte("ok"))
			}))
			defer app.Close()
			s := start(t, func(c *Config) {
				c.Upstream = mustURL(app.URL)
				c.CRS.RequestBodyLimit = 1 << 20
				if own {
					c.CRS.UploadDir = mine
				}
			})
			done := make(chan int)
			go func() {
				status, _ := s.raw(t, uploadRequest(multipartBody(filePart("photo.jpg", "an ordinary picture"))))
				done <- status
			}()
			select {
			case <-atApp:
			case <-time.After(5 * time.Second):
				t.Fatal("the request never reached the application")
			}
			count := func(dir string) int {
				entries, _ := os.ReadDir(dir)
				return len(entries)
			}
			inShared, inMine := count(shared), count(mine)
			close(release)
			if status := <-done; status != 200 {
				t.Fatalf("status %d", status)
			}
			if own && (inMine != 1 || inShared != 0) {
				t.Fatalf("while the request ran: %d file(s) in the proxy's directory and %d in the shared one; want 1 and 0", inMine, inShared)
			}
			if !own && inShared != 1 {
				t.Fatalf("with no directory set, the control run found %d file(s) in the shared one, want 1 (so the test can see them)", inShared)
			}
			if count(mine) != 0 || count(shared) != 0 {
				t.Fatalf("files were left behind: %d and %d", count(mine), count(shared))
			}
		})
	}
}
