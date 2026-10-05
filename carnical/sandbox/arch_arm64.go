//go:build linux && arm64

package sandbox

const (
	auditArch      = 0xC00000B7 // AUDIT_ARCH_AARCH64
	auditArchX8664 = 0
)
