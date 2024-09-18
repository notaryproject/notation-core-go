package file

import "io"

// Using is a helper function to ensure that a resource is closed after using it
// and return the error if any.
func Using[T io.Closer](t T, f func(t T) error) (err error) {
	defer func() {
		if closeErr := t.Close(); closeErr != nil && err == nil {
			err = closeErr
		}
	}()
	return f(t)
}
