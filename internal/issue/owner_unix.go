//go:build unix

package issue

import (
	"os"
	"syscall"
)

// adoptOwner gives the replacement file the owner of the one it replaces.
//
// Best effort on purpose: only root can chown to another user, and an operator
// who already owns the file needs no chown at all. The case it exists for is the
// ordinary deployment — a credential file owned by the relay's service user,
// edited by root — where a rename that quietly changed the owner produces a file
// the relay cannot read. That failure surfaces at the next SIGHUP as a reload
// that keeps the old set, or at the next boot as a relay that refuses to start,
// and in both cases hours after the mint that caused it.
func adoptOwner(replacing string, temp *os.File) {
	info, err := os.Stat(replacing)
	if err != nil {
		return
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return
	}
	_ = temp.Chown(int(stat.Uid), int(stat.Gid))
}
