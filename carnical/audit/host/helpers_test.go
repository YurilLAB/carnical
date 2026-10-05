package host

import (
	"net"
	"os/exec"
	"os/user"
	"testing"
)

func execCommand(name string, args ...string) *exec.Cmd { return exec.Command(name, args...) }

func listenOnce(t *testing.T) (net.Listener, int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return ln, ln.Addr().(*net.TCPAddr).Port
}

func currentUserName(t *testing.T) string {
	t.Helper()
	u, err := user.Current()
	if err != nil {
		t.Skip("cannot find the current user")
	}
	return u.Username
}
