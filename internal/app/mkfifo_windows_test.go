//go:build windows

package app

import "fmt"

func mkfifoForTest(path string, mode uint32) error {
	return fmt.Errorf("mkfifo not supported on windows for test path %q", path)
}
