//go:build linux && amd64

package sandbox

const (
	auditArch      = 0xC000003E // AUDIT_ARCH_X86_64
	auditArchX8664 = 0xC000003E
)
