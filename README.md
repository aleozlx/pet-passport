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

A report is prose, not a table, and its exact wording is free to change between releases.
Here is a short excerpt from running the tool against `C:\Windows\System32\notepad.exe`:

```
Pet Passport <version> read "C:\\Windows\\System32\\notepad.exe". This is a static reading of
that one file, not a judgment about it.

Self-reported identity (unverified)
The file is 360448 bytes and its SHA-256 is 468ffe129c395abf6b21a09efdf261910a95fb98aa982e...
The self-reported product name is "Microsoft® Windows® Operating System"; it is unverified.
...
api-ms-win-core-file-l1-1-0.dll imports DeleteFileW. Deletes a file (DeleteFileW).
USER32.dll imports GetDC. Obtains a device context for a window or the screen (GetDC).
...

Blind spots in this static reading
No TLS callbacks were found in the TLS directory; this does not rule out code running
before ordinary application behavior by other mechanisms.
```

### Status

[`docs/design.md`](docs/design.md) is the current thinking — read it before proposing a
feature, particularly the non-goals, which are deliberate refusals rather than unfinished
work. Contributions: [`CONTRIBUTING.md`](CONTRIBUTING.md).

Apache-2.0.
