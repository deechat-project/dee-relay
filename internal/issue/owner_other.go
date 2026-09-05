//go:build !unix

package issue

import "os"

// adoptOwner is a no-op where there is no uid to adopt. The relay deploys on
// Linux; this exists so the tool still builds on an operator's other machine.
func adoptOwner(replacing string, temp *os.File) {}
