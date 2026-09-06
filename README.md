# Pet Passport

A desktop pet wants permissions that would be alarming almost anywhere else. It draws on
top of everything, it follows your cursor, and it may want to see your screen, reach the
network, or start when you log in. Some of that is what makes a pet a pet. Some of it is
indistinguishable from what you would not want running.

Pet Passport reads a pet binary and reports, as specifically as it can, what that binary
appears able to do.

It does not tell you whether the answer is acceptable. There is **no pass or fail, no
score, no badge, and no claim that anything is safe** — those depend on what you wanted and
who you trust, which is not a program's call to make. You read the report and decide.

## Why a separate tool you fetch yourself

A checker distributed by the party being checked can always have been doctored. A copy of
the passport may ship alongside a pet as a convenience, but that copy is never the basis of
anything: the point is that **you can fetch a fresh passport yourself**, from here, and run
it against any pet you like — including pets it has never seen, and pets released long
after the passport was built.

Because a pet binary is frozen when it ships and this tool is not, an author cannot evade a
checker that did not exist when they built. No release ever passes out of reach of
re-examination.

## What it is not

It reads a file. It cannot see what a program does once it is running. If you want to know
what a pet *actually does* rather than what it *appears able to do*, reach for a runtime
tool — a system call monitor, a network capture, a debugger.

This is one instrument, offered in the belief that you should be able to check things
yourself. It is not the answer, and it will tell you where it cannot see.

## Status

Early. The [design document](docs/design.md) is the current state of thinking — including
the non-goals, which are deliberate refusals rather than unfinished work, and the open
questions that are genuinely unsettled. Read it before proposing a feature.

## License

Apache-2.0. See [LICENSE](LICENSE).
