package optional

// SVIDOptionals contains optional fields for SVIDs.
type SVIDOptionals struct {
	// Hint is an operator-specified string used to provide guidance on how this
	// identity should be used by a workload when more than one SVID is returned.
	Hint string
}

type SVIDOption func(*SVIDOptionals)

func WithHint(hint string) SVIDOption {
	return func(svid *SVIDOptionals) {
		svid.Hint = hint
	}
}
