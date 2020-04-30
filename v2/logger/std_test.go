package logger_test

import (
	"bytes"
	"log"
	"testing"

	"github.com/spiffe/go-spiffe/v2/logger"
	"github.com/stretchr/testify/require"
)

func TestStd(t *testing.T) {
	buf := new(bytes.Buffer)
	log.SetOutput(buf)
	log.SetFlags(0)

	logger.Std.Debugf("%s", "debug")
	logger.Std.Warnf("%s", "warn")
	logger.Std.Infof("%s", "info")
	logger.Std.Errorf("%s", "error")

	require.Equal(t, `[DEBUG] debug
[WARN] warn
[INFO] info
[ERROR] error
`, buf.String())
}
