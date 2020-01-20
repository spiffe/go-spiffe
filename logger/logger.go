package logger

// Logger is a logging interface used to log information
type Logger interface {
	Debugf(format string, args ...interface{})
	Infof(format string, args ...interface{})
	Warnf(format string, args ...interface{})
	Errorf(format string, args ...interface{})
}

type NullLogger struct{}

func (NullLogger) Debugf(format string, args ...interface{}) {}
func (NullLogger) Infof(format string, args ...interface{})  {}
func (NullLogger) Warnf(format string, args ...interface{})  {}
func (NullLogger) Errorf(format string, args ...interface{}) {}
