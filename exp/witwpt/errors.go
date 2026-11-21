package witwpt

import "fmt"

func wrapErr(err error) error {
	return fmt.Errorf("witwpt: %w", err)
}
