//go:build !windows

package main

// maybePause is a no-op on non-Windows platforms. The vanishing-console
// problem it works around on Windows - a shell that spawns a throwaway
// console per double-clicked process and destroys it (and everything
// printed to it) the instant the process exits - does not exist elsewhere:
// a graphical launcher on macOS or Linux does not attach a fresh terminal to
// the process at all, so there is no console output to lose in the first
// place, and nothing to hold open here.
func maybePause() {}
