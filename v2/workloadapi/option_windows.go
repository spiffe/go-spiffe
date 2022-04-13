//go:build windows
// +build windows

package workloadapi

// WithNamedPipeName provides a Pipe Name for the Workload API
// endpoint in the form \\.\pipe\<PipeName>.
func WithNamedPipeName(namedPipeName string) ClientOption {
	return clientOption(func(c *clientConfig) {
		c.namedPipeName = namedPipeName
	})
}
