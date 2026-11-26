// Package slogutil adapts a *slog.Logger to the logger.Logger interface used
// throughout the library.
package slogutil

import (
	"context"
	"fmt"
	"log/slog"
	"runtime"
	"time"

	"github.com/spiffe/go-spiffe/v2/logger"
)

// Wrap returns a logger.Logger that writes to the given *slog.Logger. A nil
// *slog.Logger disables logging.
func Wrap(l *slog.Logger) logger.Logger {
	if l == nil {
		return logger.Null
	}
	return slogAdapter{l: l}
}

type slogAdapter struct {
	l *slog.Logger
}

func (a slogAdapter) Debugf(format string, args ...any) {
	a.log(slog.LevelDebug, format, args)
}

func (a slogAdapter) Infof(format string, args ...any) {
	a.log(slog.LevelInfo, format, args)
}

func (a slogAdapter) Warnf(format string, args ...any) {
	a.log(slog.LevelWarn, format, args)
}

func (a slogAdapter) Errorf(format string, args ...any) {
	a.log(slog.LevelError, format, args)
}

func (a slogAdapter) log(level slog.Level, format string, args []any) {
	ctx := context.Background()
	// Skip formatting the message when the level is disabled.
	if !a.l.Enabled(ctx, level) {
		return
	}
	// Record the caller of Debugf/Infof/Warnf/Errorf as the source instead of
	// this adapter. Skip runtime.Callers, this function and the level method.
	var pcs [1]uintptr
	runtime.Callers(3, pcs[:])
	r := slog.NewRecord(time.Now(), level, fmt.Sprintf(format, args...), pcs[0])
	_ = a.l.Handler().Handle(ctx, r)
}
