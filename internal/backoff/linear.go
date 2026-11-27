package backoff

import (
	"math"
	"time"
)

// Linear defines a linear backoff policy.
type Linear struct {
	initialDelay time.Duration
	maxDelay     time.Duration
	n            int
}

// NewLinear returns a new linear backoff.
func NewLinear() *Linear {
	return &Linear{
		initialDelay: time.Second,
		maxDelay:     30 * time.Second,
		n:            0,
	}
}

// Next returns the next backoff period.
func (b *Linear) Next() time.Duration {
	backoff := float64(b.n) + 1
	d := math.Min(b.initialDelay.Seconds()*backoff, b.maxDelay.Seconds())
	b.n++
	return time.Duration(d) * time.Second
}

// Reset resets the backoff.
func (b *Linear) Reset() {
	b.n = 0
}
