package logger_test

import (
	"bytes"
	"testing"

	"github.com/spiffe/go-spiffe/v2/logger"
	"github.com/stretchr/testify/require"
)

func TestWriter(t *testing.T) {
	buf := new(bytes.Buffer)

	log := logger.Writer(buf)

	log.Debugf("%s", "debug")
	log.Warnf("%s", "warn")
	log.Infof("%s", "info")
	log.Errorf("%s", "error")

	require.Equal(t, `[DEBUG] debug
[WARN] warn
[INFO] info
[ERROR] error
`, buf.String())
}
