// Package logger provides a logger interface and simple implementations.
//
// The implementation lives in
// [github.com/spiffe/go-spiffe/lite/logger].
// This package re-exports it so that existing importers of
// github.com/spiffe/go-spiffe/v2 continue to work unchanged. See that
// package for full documentation.
package logger

import lite "github.com/spiffe/go-spiffe/lite/logger"

// Type aliases. These must be aliases rather than definitions so that values
// cross the module boundary and interface satisfaction is preserved.
type (
	// Logger provides logging facilities to the library.
	Logger = lite.Logger
)

var (
	// Null is a no-op logger. It is used to suppress logging and is the default logger for the library.
	Null = lite.Null

	// Std is a logger that uses the Go standard log library.
	Std = lite.Std

	// Writer provides a logger that outputs logging to the given writer.
	Writer = lite.Writer
)
