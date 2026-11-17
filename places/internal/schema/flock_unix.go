//go:build unix

package schema

import (
	"fmt"
	"os"
	"syscall"
)

func flock(f *os.File, exclusive bool) error {
	how := syscall.LOCK_SH
	if exclusive {
		how = syscall.LOCK_EX
	}
	if err := syscall.Flock(int(f.Fd()), how|syscall.LOCK_NB); err != nil {
		if err == syscall.EWOULDBLOCK {
			return errLocked
		}
		return fmt.Errorf("flock: %w", err)
	}
	return nil
}
