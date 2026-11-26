package slogutil_test

import (
	"bytes"
	"log/slog"
	"testing"

	"github.com/spiffe/go-spiffe/v2/internal/slogutil"
	"github.com/spiffe/go-spiffe/v2/logger"
	"github.com/stretchr/testify/require"
)

func TestWrap(t *testing.T) {
	buf := new(bytes.Buffer)
	l := slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{
		Level: slog.LevelDebug,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if a.Key == slog.TimeKey && len(groups) == 0 {
				return slog.Attr{}
			}
			return a
		},
	}))

	log := slogutil.Wrap(l)
	log.Debugf("%s", "debug")
	log.Infof("%s %d", "info", 1)
	log.Warnf("%s", "warn")
	log.Errorf("%s", "error")

	require.Equal(t, `level=DEBUG msg=debug
level=INFO msg="info 1"
level=WARN msg=warn
level=ERROR msg=error
`, buf.String())
}

func TestWrapRespectsLevel(t *testing.T) {
	buf := new(bytes.Buffer)
	l := slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelWarn}))

	log := slogutil.Wrap(l)
	log.Debugf("debug")
	log.Infof("info")
	require.Empty(t, buf.String())

	log.Warnf("warn")
	require.Contains(t, buf.String(), "msg=warn")
}

func TestWrapNil(t *testing.T) {
	require.Equal(t, logger.Null, slogutil.Wrap(nil))
}
