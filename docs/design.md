# Pet Passport — design

A desktop pet is a small program that sits on your screen and, by its nature, wants
permissions that would be alarming almost anywhere else. It draws on top of everything.
It follows your cursor. It may want to see the screen, or talk to the network, or start
when you log in. Some of that is exactly what makes a pet a pet, and some of it is
indistinguishable from what you would not want running.

Pet Passport reads a pet binary and tells you, as specifically as it can, what the binary
appears able to do. That is the whole product. It does not tell you whether the answer is
acceptable — that depends on what you wanted, what the pet's author advertised, and how
much you trust them, none of which a program is in a position to judge.

## Trust model

The passport is open source and independently obtainable. A copy may be distributed
alongside a pet as a convenience, but that copy is never the basis of the guarantee: a
checker shipped by the party being checked can always have been doctored. The security
property comes entirely from the fact that **you can fetch a fresh passport yourself** and
run it against any pet you like.

This has a pleasant consequence. Because the bundled copy is only a convenience, it does
not need to be signed, hash-verified, or protected in any way, and a hostile author gains
nothing by tampering with theirs. Anyone who cares fetches their own; anyone who doesn't
was not relying on it. The design does not have to defend the bundled copy, because the
bundled copy was never load-bearing.

It is worth being explicit about the corollary: **Pet Passport is one instrument, not the
answer.** It reads a file. It cannot see what a program does once it is running. If you
want to know what a pet actually does rather than what it appears able to do, that is a
job for a runtime tool — a system call monitor, a network capture, a debugger — and the
passport should say so rather than let its own silence imply sufficiency.

## What it reports

**As specific as the evidence allows.** Capability summaries are where honesty goes to
die, because abstraction is where judgment sneaks back in. The same underlying call can be
the mechanism of something benign or something hostile, and a coarse label picks a side.

A program that polls a keyboard-state function for two mouse buttons, in order to notice
when you release a drag, is doing something entirely ordinary. A program that polls the
same function across the whole keyboard is doing something else. "Reads keyboard input" is
true of both and useful for neither. Reporting the actual imported symbol, and what it was
narrowed to where that is visible, lets a reader see the difference. Likewise, a program
that marks its own window as excluded from screen capture may be hiding from you, or may
simply be a screen-drawing tool that does not want to appear in its own screenshots — the
specific fact is short, checkable, and lets the reader decide, while any summary of it has
already editorialised.

So: the specific observation is the record. Grouping and headings are a rendering over
that record to make it navigable, never a replacement for it, and they should be named
after the mechanism rather than a presumed intent.

**Incompleteness is a finding, not silence.** Static reading has well-known limits. A
binary can resolve functions at runtime so their names never appear in the import table;
it can be packed so that the real imports are reconstructed only in memory; it can invoke
the operating system directly and skip the documented layer entirely. None of these are
exotic.

The failure mode this creates is not a wrong answer, it is a *quiet* one: an obfuscated
binary produces a short, clean-looking report, and a reader takes the quiet for innocence.
So the report must say what it could not see. "This binary resolves imports at runtime;
the static picture is partial" is as much an observation about the artifact as any import
is, and omitting it is the one way a purely descriptive tool can still mislead.

## Version independence

Any passport version is expected to run against any pet, including pets built long before
or long after it. This is deliberate, and it is worth stating why, because the natural
engineering instinct cuts the other way.

A pet binary is frozen the moment it ships. The passport is not. If a user can run
tomorrow's passport against a binary released two years ago, then **an author cannot
evade a checker that did not exist when they built**, and no release ever passes out of
reach of re-examination. That asymmetry is the most valuable property in this design, and
it exists only if nothing gets in the way of arbitrary combinations.

Concretely:

- **No release is ever withdrawn or expired.** Every published passport version stays
  downloadable indefinitely. If old versions disappear, the comparison disappears with
  them.
- **No version gating.** A passport must never refuse a binary for being newer than it, or
  built by a toolchain it does not recognise. Unknown must degrade to "here is what I
  could see," never to an error.
- **Every report states what produced it** — which binary, and which passport — because a
  report is only meaningful as one point in a set of possible combinations.

Running several combinations is a legitimate way to use this tool, not a misuse of it. The
differences between reports carry information that no single report does.

## The output is for people

Reports are written to be read by a human being. **There is no output schema and no
stability guarantee**, now or later.

This is not laziness, it is load-bearing. A stable machine-readable format is a contract,
and contracts get conscripted: someone builds a dashboard on it, then a gate, then a
badge, and the tool has acquired a verdict it never issued and cannot stand behind.
Refusing the schema is what prevents a descriptive instrument from being drafted into
service as an authority. It also frees each release to describe what it found in whatever
shape that evidence deserves, instead of forcing new kinds of observation into a shape
fixed years earlier — which in turn is what makes keeping every old release cheap, since
old releases are frozen artifacts rather than interfaces anyone owes maintenance on.

A disclaimer alone will not achieve this. Anything printed will eventually be parsed by
someone regardless of what the documentation says, so the format should be actively
unpleasant to depend on: prose and full sentences rather than fixed columns, no aligned
fields inviting a split on whitespace, and no reluctance to change phrasing between
releases.

## Non-goals

These are refusals, not gaps. Each one is something a well-intentioned contributor will
eventually propose, with a reasonable argument, and each one individually sounds like a
small improvement. Together they would reconstitute exactly the authority this project
declines to hold. **Do not add these silently.**

- **No pass or fail.** The tool reports; it does not conclude. There is no verdict, no
  score, no severity ranking, no risk rating, and no threshold above which something is
  called a problem.
- **No badge, seal, or certification.** Nothing this project publishes may be embedded by
  a pet author to signal approval. There is no approval to signal.
- **No claim that anything is safe.** The tool has no basis for such a claim and will not
  imply one, including by omission or by a reassuring absence of output.
- **No output schema.** See above. This includes a `--json` flag, however convenient.
- **No summary line.** A one-line précis at the top of a report is a verdict wearing a
  different hat, and it is the format everyone will quote.
- **No claim of completeness.** The tool names its own blind spots and points at other
  instruments rather than implying it is sufficient on its own.
- **No registry, database, or aggregated results service.** Collected reports become a
  reputation system, and a reputation system is a verdict with extra steps.
- **No integrity checking of a bundled copy of itself.** It is not the trust root; fetching
  a fresh copy is. Building self-verification would advertise a guarantee that does not
  exist.

## Open questions

- **Determinism.** Should the same binary and the same passport version always produce
  byte-identical output? It is a different property from a schema — the argument for it is
  that two people running the same combination can corroborate each other instead of
  arguing about whose output is real. The argument against is that it is one more property
  to preserve, and it sits close to the parseability this design is trying to discourage.
- **Scope of the observation engine.** Import tables and strings are the obvious starting
  point. Many desktop applications embed their user interface as web assets inside the
  binary, and behaviour expressed there is invisible to an import-table reading; deciding
  whether the passport unpacks and reports on embedded assets substantially changes what
  it can see, and how much work it is.
- **Platforms.** Windows is the first target. macOS and Linux binaries have their own
  equivalents of everything described here, and none of the design above is
  Windows-specific, but the observation engine will be.
- **Identity metadata.** A pet may carry self-declared identifying information such as a
  name and version. This is self-asserted and must be reported as such — "self-reported
  name" rather than "name" — but the format and location of that declaration are not
  settled.
