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

### Status

Early; no implementation yet. [`docs/design.md`](docs/design.md) is the current thinking —
read it before proposing a feature, particularly the non-goals, which are deliberate
refusals rather than unfinished work. Contributions: [`CONTRIBUTING.md`](CONTRIBUTING.md).

Apache-2.0.
