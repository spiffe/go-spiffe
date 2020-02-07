package logger

var Null Logger = NullLogger{}

type NullLogger struct{}

func (NullLogger) Debugf(format string, args ...interface{}) {}
func (NullLogger) Infof(format string, args ...interface{})  {}
func (NullLogger) Warnf(format string, args ...interface{})  {}
func (NullLogger) Errorf(format string, args ...interface{}) {}
