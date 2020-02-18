package logger

import (
	"fmt"
	"io"
)

// Writer provides a logger that outputs logging to the given writer.
func Writer(w io.Writer) Logger {
	return writer{Writer: w}
}

type writer struct {
	io.Writer
}

// Debugf outputs debug logging
func (w writer) Debugf(format string, args ...interface{}) {
	fmt.Fprintf(w.Writer, "[DEBUG]: "+format, args...)
}

// Infof outputs info logging
func (w writer) Infof(format string, args ...interface{}) {
	fmt.Fprintf(w.Writer, "[INFO]: "+format, args...)
}

// Warnf outputs warn logging
func (w writer) Warnf(format string, args ...interface{}) {
	fmt.Fprintf(w.Writer, "[WARN]: "+format, args...)
}

// Errorf outputs error logging
func (w writer) Errorf(format string, args ...interface{}) {
	fmt.Fprintf(w.Writer, "[ERROR]: "+format, args...)
}
