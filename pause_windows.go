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
	kernel32           = syscall.NewLazyDLL("kernel32.dll")
	procGetConsoleMode = kernel32.NewProc("GetConsoleMode")
)

// maybePause prints a prompt and waits for a line on stdin before the process
// exits, whenever stdout is a console. Double-clicking the exe in Explorer
// gives it a fresh console that disappears the instant the process exits, so
// without this a double-clicked run - a failing one especially - would vanish
// before anyone could read it. It pauses unconditionally rather than trying
// to guess whether it was double-clicked: the guess is one more thing to get
// wrong, and a console reader may be replaced by a window later anyway. The
// one exception is a redirected stdout (a file or a pipe), where there is no
// console to vanish and a pause would only hang whatever is reading the
// output.
func maybePause() {
	if !stdoutIsConsole() {
		return
	}
	fmt.Println("Press Enter to close.")
	bufio.NewReader(os.Stdin).ReadString('\n')
}

// stdoutIsConsole reports whether os.Stdout is attached to a console, as
// opposed to redirected to a file or a pipe. GetConsoleMode only succeeds on
// a real console handle.
func stdoutIsConsole() bool {
	var mode uint32
	ret, _, _ := procGetConsoleMode.Call(os.Stdout.Fd(), uintptr(unsafe.Pointer(&mode)))
	return ret != 0
}
