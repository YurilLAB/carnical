//go:build !(linux && (amd64 || arm64))

package sandbox

// Apply is not available on this system.
func Apply(Policy) (Report, error) { return Report{}, ErrUnsupported }

// ThreadStatus is what the kernel says about one thread's restrictions.
type ThreadStatus struct {
	TID        int
	NoNewPrivs bool
	Seccomp    int
}

// Threads is not available on this system.
func Threads() ([]ThreadStatus, error) { return nil, ErrUnsupported }
