package witwpt

import (
	"errors"
	"fmt"
)

// errReplayed is the cause reported when a proof's jti has already been
// recorded. It is unexported because callers distinguish failures by Stage.
var errReplayed = errors.New("proof token has already been used")

// Stage identifies which step of verification rejected a request, so a
// rejection can be counted and not only logged.
type Stage int

const (
	// StageWIT covers validating the WIT-SVID against the trust bundle: its typ,
	// kid, signature, expiry, subject, and confirmation key.
	StageWIT Stage = iota + 1

	// StageProof covers verifying the WPT against the confirmation key the
	// WIT-SVID named, including its binding to that credential and to the target.
	StageProof

	// StageReplay covers a proof whose jti has already been recorded.
	StageReplay
)

var stageNames = map[Stage]struct{ label, failure string }{
	StageWIT:    {"wit", "WIT-SVID validation failed"},
	StageProof:  {"proof", "proof verification failed"},
	StageReplay: {"replay", "replay check failed"},
}

// String returns a short, stable label suitable for use as a metric dimension.
func (s Stage) String() string {
	if name, ok := stageNames[s]; ok {
		return name.label
	}
	return "unknown"
}

// Error is a verification failure together with the stage that produced it.
// Verify returns errors of this type so an error handler can count rejections
// by stage while the remote caller is told only that it was refused.
type Error struct {
	Stage Stage
	Err   error
}

func (e *Error) Error() string {
	failure := "verification failed"
	if name, ok := stageNames[e.Stage]; ok {
		failure = name.failure
	}
	return fmt.Sprintf("witwpt: %s: %v", failure, e.Err)
}

func (e *Error) Unwrap() error { return e.Err }

// newError builds a staged verification error.
func newError(stage Stage, err error) error {
	return &Error{Stage: stage, Err: err}
}

func wrapErr(err error) error {
	return fmt.Errorf("witwpt: %w", err)
}
