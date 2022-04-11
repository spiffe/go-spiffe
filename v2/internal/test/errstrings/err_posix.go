//go:build !windows
// +build !windows

// OS specific error strings
package errstrings

var (
	FileNotFound = "no such file or directory"
	NetClosing   = "use of closed network connection"
)
