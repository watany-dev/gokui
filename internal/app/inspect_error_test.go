package app

import (
	"errors"
	"fmt"
	"testing"
)

func TestIsInspectSourceNotFoundError(t *testing.T) {
	t.Run("matches sentinel and wrapped sentinel", func(t *testing.T) {
		if !isInspectSourceNotFoundError(errInspectSourceNotFound) {
			t.Fatal("expected sentinel to match")
		}
		wrapped := fmt.Errorf("wrapped: %w", errInspectSourceNotFound)
		if !isInspectSourceNotFoundError(wrapped) {
			t.Fatal("expected wrapped sentinel to match")
		}
	})

	t.Run("does not match text-only error", func(t *testing.T) {
		err := errors.New("inspect source not found: /tmp/skill")
		if isInspectSourceNotFoundError(err) {
			t.Fatal("did not expect text-only error to match")
		}
	})
}
