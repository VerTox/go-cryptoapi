//go:build linux

package csp

import (
	"os"
	"testing"
)

// loadFixture reads a testdata file and skips the test/benchmark if it is
// missing. See csp/testdata/README.md for how to provision fixtures locally.
func loadFixture(tb testing.TB, name string) []byte {
	tb.Helper()

	data, err := os.ReadFile(name)
	if err != nil {
		if os.IsNotExist(err) {
			tb.Skipf("fixture missing: %s (see csp/testdata/README.md)", name)
		}
		tb.Fatalf("read %s: %v", name, err)
	}
	return data
}
