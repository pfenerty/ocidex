package jobqueue

import (
	"errors"
	"fmt"
)

// ErrPermanent marks an error as not worth retrying. A processor returning an
// error that wraps it tells Worker.run to fail the row immediately rather than
// spend the remaining retry budget re-running work that cannot succeed.
var ErrPermanent = errors.New("permanent")

// Permanent marks err as non-retryable. The result matches both
// errors.Is(_, ErrPermanent) and errors.Is(_, err), and its message keeps the
// "permanent: " prefix so the stored last_error records why the job was not
// retried. Returns nil for a nil err so it is safe to apply unconditionally.
func Permanent(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%w: %w", ErrPermanent, err)
}
