# Pet Passport

Reads a desktop pet binary and reports, as specifically as it can, what that binary appears
able to do.

It does not tell you whether that is acceptable. **No pass or fail, no score, no badge, no
claim that anything is safe** — that depends on what you wanted and who you trust, which is
not a program's call. You read the report and decide.

### Fetch it yourself

A checker distributed by the party being checked can always have been doctored. A copy may
ship alongside a pet as a convenience, but that copy is never the basis of anything: the
point is that you can fetch a fresh passport from here and run it against any pet — including
pets released long after the passport was built. A pet binary is frozen when it ships and
this tool is not, so **an author cannot evade a checker that did not exist when they built**.

### What it is not

It reads a file. It cannot see what a program does while running — for that, reach for a
system call monitor, a network capture, or a debugger. This is one instrument, offered in
the belief that you should be able to check things yourself. It will tell you where it
cannot see.

### Get a release binary

Download `pet-passport-<version>-<os>-<arch>` and `SHA256SUMS` from the
[releases page](https://github.com/aleozlx/pet-passport/releases) for the platform you're on
(`windows-amd64`, `linux-amd64`, or `darwin-arm64`), then check the binary against the
published hash before running it:

```
sha256sum -c SHA256SUMS                              # Linux/macOS
Get-FileHash pet-passport-<version>-windows-amd64.exe -Algorithm SHA256   # Windows PowerShell, compare against SHA256SUMS
```

Each release's notes state the exact Go version and build command used, so the build is
reproducible by anyone.

### Build from source

Requires only the Go toolchain named in [`go.mod`](go.mod) — no other dependencies.

```
git clone https://github.com/aleozlx/pet-passport
cd pet-passport
go build
```

### Run it

```
pet-passport C:\path\to\some-pet.exe
```

Run it with no arguments and it examines every Windows PE file it finds directly in the
current directory instead (not recursive). It first prints a short paragraph naming the files
it is about to examine, in order, each with its self-reported product name and version if it
has one, then each file's full report in turn, separated by a delimiter line, followed by a
closing paragraph naming anything present that was not a PE image and so was not examined.
Every file gets the same full report; the one exception is ordering, not content: a file
whose SHA-256 happens to match the running passport's own is moved to the end, since a report
about the tool checking itself is the least interesting one to the person who ran it.

Double-clicking the exe in Explorer opens a console that closes the instant the program
exits, so on Windows Pet Passport always prints `Press Enter to close.` and waits before
exiting when its output is going to a console. Redirect the output to a file and it exits
immediately.

A report is prose, not a table, and its exact wording is free to change between releases.
Here is a short excerpt from running the tool against `C:\Windows\System32\notepad.exe`:

```
Pet Passport <version> read "C:\\Windows\\System32\\notepad.exe". This is a static reading of
that one file, not a judgment about it.

Identity (self-reported, unverified)
The self-reported product name is "Microsoft® Windows® Operating System"; it is unverified.
The self-reported product version is "10.0.26100.9278"; it is unverified.
The self-reported company is "Microsoft Corporation"; it is unverified.
The file is 360448 bytes and its SHA-256 is 468ffe129c395abf6b21a09efdf261910a95fb98aa982e...

Described mechanisms
api-ms-win-core-file-l1-1-0.dll imports DeleteFileW. Deletes a file (DeleteFileW).
USER32.dll imports GetDC. Obtains a device context for a window or the screen (GetDC).
...

Blind spots in this static reading
No TLS callbacks were found in the TLS directory; this does not rule out code running
before ordinary application behavior by other mechanisms.
...

Appendix: every imported symbol, by DLL
These are all of the imported symbols this static reading observed, grouped by the DLL that
exports them. This tool has not assigned most of them a more specific description above; a
name appearing here only means it was imported, not that it was examined.
...
```

Identity, then the mechanisms the mapping table can name, come first; the full symbol-by-DLL
inventory - hundreds of names on a real GUI application - is an appendix at the end, so it
doesn't bury the few sentences that say something specific.

### Status

[`docs/design.md`](docs/design.md) is the current thinking — read it before proposing a
feature, particularly the non-goals, which are deliberate refusals rather than unfinished
work. Contributions: [`CONTRIBUTING.md`](CONTRIBUTING.md).

Apache-2.0.
