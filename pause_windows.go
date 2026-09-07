//go:build windows

package main

import (
	"bufio"
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

var (
	kernel32                  = syscall.NewLazyDLL("kernel32.dll")
	procGetConsoleMode        = kernel32.NewProc("GetConsoleMode")
	procGetConsoleProcessList = kernel32.NewProc("GetConsoleProcessList")
)

// maybePause prints a prompt and waits for a line on stdin when this process
// is the only one attached to its console. That is what double-clicking the
// exe in Explorer looks like from inside the process: Windows spawns a fresh
// console just to host it, and that console (with everything printed to it)
// disappears the instant the process exits, so a failing double-clicked run
// would otherwise vanish before anyone could read why. Launched from an
// existing shell, the shell is attached to the same console too, so the
// count is greater than one and this is a no-op - a double-clicked run pauses,
// a shell-launched run exits immediately like any other CLI.
func maybePause() {
	if !stdoutIsConsole() {
		return
	}
	if !isSoleConsoleProcess() {
		return
	}
	fmt.Println("Press Enter to close.")
	bufio.NewReader(os.Stdin).ReadString('\n')
}

// stdoutIsConsole reports whether os.Stdout is attached to a console, as
// opposed to redirected to a file or a pipe. GetConsoleMode only succeeds on
// a real console handle, so this doubles as the "stdout is not a terminal"
// check.
func stdoutIsConsole() bool {
	var mode uint32
	ret, _, _ := procGetConsoleMode.Call(os.Stdout.Fd(), uintptr(unsafe.Pointer(&mode)))
	return ret != 0
}

// isSoleConsoleProcess reports whether this process is the only process
// attached to its console.
func isSoleConsoleProcess() bool {
	// GetConsoleProcessList's return value is always the true number of
	// processes attached to the console, even when that number exceeds the
	// size of the buffer passed in, so a one-element buffer is enough to
	// learn the count.
	var pid uint32
	ret, _, _ := procGetConsoleProcessList.Call(uintptr(unsafe.Pointer(&pid)), 1)
	return ret == 1
}
