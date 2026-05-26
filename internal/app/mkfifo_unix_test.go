//go:build !windows

package app

import "syscall"

func mkfifoForTest(path string, mode uint32) error {
	return syscall.Mkfifo(path, mode)
}
