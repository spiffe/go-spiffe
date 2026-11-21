package witwpt

import (
	"errors"
	"fmt"
)

// ErrReplayed is returned by a ReplayCache for a proof it has already recorded.
var ErrReplayed = errors.New("proof token has already been used")

// Stage identifies which step of verification rejected a request, so a
// rejection can be counted and not only logged.
type Stage int

const (
	// StageWIT covers validating the WIT-SVID against the trust bundle.
	StageWIT Stage = iota + 1

	// StageProof covers verifying the WPT and its binding to the WIT-SVID and target.
	StageProof

	// StageReplay covers a proof whose jti has already been recorded.
	StageReplay

	// StageReplayCache covers a ReplayCache that failed to check or record a proof.
	StageReplayCache
)

var stageNames = map[Stage]struct{ label, failure string }{
	StageWIT:         {"wit", "WIT-SVID validation failed"},
	StageProof:       {"proof", "proof verification failed"},
	StageReplay:      {"replay", "replay check failed"},
	StageReplayCache: {"replay_cache", "replay cache failed"},
}

// String returns a short, stable label suitable for use as a metric dimension.
func (s Stage) String() string {
	if name, ok := stageNames[s]; ok {
		return name.label
	}
	return "unknown"
}

// Error is a verification failure tagged with the Stage that rejected it.
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

func newError(stage Stage, err error) error {
	return &Error{Stage: stage, Err: err}
}

func wrapErr(err error) error {
	return fmt.Errorf("witwpt: %w", err)
}
