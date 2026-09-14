package witwpt

import "fmt"

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

// String returns a short, stable label suitable for use as a metric dimension.
func (s Stage) String() string {
	switch s {
	case StageWIT:
		return "wit"
	case StageProof:
		return "proof"
	case StageReplay:
		return "replay"
	default:
		return "unknown"
	}
}

// Error is a verification failure together with the stage that produced it.
// Verify returns errors of this type so an error handler can count rejections
// by stage while the remote caller is told only that it was refused.
type Error struct {
	// Stage is the step that rejected the request.
	Stage Stage

	// Err is the underlying cause.
	Err error
}

func (e *Error) Error() string {
	var what string
	switch e.Stage {
	case StageWIT:
		what = "WIT-SVID validation failed"
	case StageProof:
		what = "proof verification failed"
	case StageReplay:
		what = "replay check failed"
	default:
		what = "verification failed"
	}
	return fmt.Sprintf("witwpt: %s: %v", what, e.Err)
}

func (e *Error) Unwrap() error { return e.Err }
