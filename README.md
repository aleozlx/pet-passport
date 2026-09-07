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
current directory instead (not recursive), and reports on the ones that declare themselves to
be pets — that is, the ones carrying a `pet_passport_v1` export (see below). It first prints a
short paragraph naming those files in order, each with what it declares about itself, then
each one's full report in turn, separated by a delimiter line, followed by a closing paragraph
naming everything else that was there: files examined and found not to be pets, and files that
were not PE images at all. Nothing present is left out of that account, but a folder full of
runtimes, installers and updaters does not bury the file you came for. An explicit path
argument, by contrast, reports whatever you point it at, pet or not, and says which it was.

Double-clicking the exe in Explorer opens a console that closes the instant the program
exits, so on Windows Pet Passport always prints `Press Enter to close.` and waits before
exiting when its output is going to a console. Redirect the output to a file and it exits
immediately.

A report is prose, not a table, and its exact wording is free to change between releases. The
one exception is the short labelled list it opens with. Here is an excerpt from running the
tool against `C:\Windows\System32\notepad.exe`, which is not a pet and says so:

```
Pet Passport <version>

* Product: Microsoft® Windows® Operating System
* Version: 10.0.26100.9278
* Publisher: Microsoft Corporation
* File: notepad.exe (360,448 bytes, sha256:468ffe129c395abf6b21a09efdf261910a95fb98aa9...)

No pet_passport_v1 export was found in this file, so nothing in it declares it to be a pet.
Product, version and publisher above are what the file's VERSIONINFO resource declares about
itself; nothing here verifies them.

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

A file that does carry a manifest gets `* Pet:` instead of `* Product:`, plus a `* Build ID:`
line, filled from the manifest rather than from VERSIONINFO. Identity, then the mechanisms the
mapping table can name, come first; the full symbol-by-DLL inventory - hundreds of names on a
real GUI application - is an appendix at the end, so it doesn't bury the few sentences that
say something specific.

### Declaring a pet: the `pet_passport_v1` manifest

A pet says what it is by exporting one data symbol. Everything a pet author needs is here.

**The symbol.** Export a data symbol named exactly `pet_passport_v1` from the executable's PE
export directory. The name is case-sensitive, and the `v1` in it is the schema version: a
later schema will be a different symbol name, so this one never changes meaning.

**The payload.** At that symbol's address, put NUL-terminated UTF-8 JSON — **at most 4096
bytes including the NUL**. Schema v1 is a flat object with exactly these keys:

| Key | Type | What it is |
|---|---|---|
| `schema` | number | Always `1`. |
| `name` | string | Display name, as you would write it for a person. |
| `slug` | string | Machine-friendly identifier, `[a-z0-9-]+`. |
| `version` | string | Your release version, in whatever scheme you use. |
| `build` | string | Short git hash of the build; may end in `-dirty`, or be `unknown`. |
| `publisher` | string | Who publishes it. |
| `homepage` | string | URL. Pet Passport prints it and does not visit it. |

Keys the schema does not define are reported as present and otherwise ignored, so adding your
own is harmless but pointless. Keys you leave out are reported as missing rather than guessed
at. A payload that is not valid JSON, or that runs past 4096 bytes without a NUL, produces a
report saying a `pet_passport_v1` export exists but its contents could not be read as a v1
manifest — never an error, and never a crash.

```json
{"schema":1,"name":"Tapi Lila Esculenta","slug":"tapi-lila","version":"0.1.0",
 "build":"7a9663a","publisher":"Alex","homepage":"https://example.invalid/tapi"}
```

**How to export it.** Any toolchain that can put a named data symbol in an executable's export
directory will do. In C or C++ with MSVC, clang-cl or MinGW, that is one declaration:

```c
__declspec(dllexport) const char pet_passport_v1[] =
    "{\"schema\":1,\"name\":\"Tapi Lila Esculenta\",\"slug\":\"tapi-lila\","
    "\"version\":\"0.1.0\",\"build\":\"7a9663a\",\"publisher\":\"Alex\","
    "\"homepage\":\"https://example.invalid/tapi\"}";
```

In Rust, an unmangled `pub static` holding the same bytes, together with a
`/EXPORT:pet_passport_v1` argument to the linker, does the same job. Whatever the language,
check your work with `dumpbin /exports your-pet.exe` — the symbol has to appear there, and its
address has to point at the JSON rather than at a forwarder. Fill `build` from
`git rev-parse --short HEAD` at build time, and use `unknown` when you cannot.

**What this buys, and what it does not.** It puts your name, version and build in the report
of anyone who checks your binary, and it is what makes your pet the file that gets reported
when someone runs the passport in a folder full of runtimes and installers. It is **not**
authentication, and Pet Passport says so in every report that prints it. Anyone can export
these bytes, including someone copying yours word for word. Whether a file really is the build
you published is answered by the SHA-256 the report prints, checked against a digest you
published somewhere your users already trust you to speak from — not by anything inside the
file.

### Status

[`docs/design.md`](docs/design.md) is the current thinking — read it before proposing a
feature, particularly the non-goals, which are deliberate refusals rather than unfinished
work. Contributions: [`CONTRIBUTING.md`](CONTRIBUTING.md).

Apache-2.0.
