package workloadapi

import "time"

// Trace provides optional callbacks for logging/telemetry purposes
type Trace struct {
	WatchX509ContextStart func(WatchX509ContextStartInfo) interface{}
	WatchX509ContextDone  func(WatchX509ContextDoneInfo, interface{})

	WatchJWTBundlesStart func(WatchJWTBundlesStartInfo) interface{}
	WatchJWTBundlesDone  func(WatchJWTBundlesDoneInfo, interface{})

	GotMalformedX509Context func(err error)
	GotMalformedJWTBundle   func(err error)
}

// WatchX509ContextStartInfo contains the trace information when an X.509
// context watch is starting.
type WatchX509ContextStartInfo struct {
}

// WatchX509ContextDoneInfo contains the trace information when an X.509
// context watch has finished.
type WatchX509ContextDoneInfo struct {
	// Err is the error that caused the watch to finish.
	Err error

	// RetryAfter is the interval the client will wait before retrying. If
	// zero, the watch will not be retried, which should normally only be the
	// case if the context passed into watch is done.
	RetryAfter time.Duration
}

// WatchJWTBundlesStartInfo contains the trace information when a JWT bundle
// watch is starting.
type WatchJWTBundlesStartInfo struct {
}

// WatchJWTBundlesDoneInfo contains the trace information when an JWT bundle
// watch has finished.
type WatchJWTBundlesDoneInfo struct {
	// Err is the error that caused the watch to finish.
	Err error

	// RetryAfter is the interval the client will wait before retrying. If
	// zero, the watch will not be retried, which should normally only be the
	// case if the context passed into watch is done.
	RetryAfter time.Duration
}
