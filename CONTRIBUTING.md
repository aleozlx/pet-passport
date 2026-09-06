# Contributing

Thanks for looking. Please read [`docs/design.md`](docs/design.md) first — especially the
**Non-goals** section, which will save you writing a PR that gets declined on principle
rather than on quality.

## The non-goals are not a backlog

The design refuses several things a scanner would normally have: a pass/fail verdict, a
score or severity ranking, a badge, a summary line, a stable output schema, and any claim
that a binary is safe. These are deliberate. Each removes a way for a descriptive tool to be
mistaken for — or conscripted into being — an authority.

They are not permanently beyond discussion, but the way to challenge one is to **open an
issue arguing the principle**, not to open a PR implementing the feature. A PR that adds a
`--json` flag is not a small convenience with a design implication attached; it is the design
implication.

## What is genuinely wanted

- **Observation coverage.** New ways to read what a binary appears able to do, and new
  evidence sources. Breadth here is the point.
- **Blind-spot reporting.** Ways to detect and clearly state that the static picture is
  incomplete — packing, runtime symbol resolution, anything that makes a report quieter than
  the truth. A missed blind spot is worse than a missed capability.
- **Wording that is more specific.** If a report says something vaguer than the evidence
  supports, that is a bug. See below.
- **Accuracy corrections.** If the tool describes something in a way that is misleading about
  the mechanism, say so, ideally with a reference.

## Wording changes are mapping changes

The mapping from evidence to the words used to describe it is what this project's
credibility rests on, more than the scanner. So:

- Be **as specific as the evidence allows**. The same underlying call can be the mechanism of
  something ordinary or something hostile; a coarse label picks a side. Report what was
  observed, and what it was narrowed to where that is visible.
- Name the **mechanism, not the intent**. "Excludes its own window from screen capture" is an
  observation. "Hides from screenshots" is an accusation.
- Never let a summary replace the specific record. Grouping is a rendering for navigation.

A PR that changes report wording should say what evidence the new wording is claiming, and
why it is not asserting more than the tool actually saw.

## Reports are prose, on purpose

Output has no schema and no stability guarantee, and the format is intentionally awkward to
parse — prose rather than aligned columns, phrasing free to change between releases. Please
do not "tidy" output into something machine-readable, and please do not build tooling that
depends on its shape; that dependency is exactly what the design is avoiding.

## Version independence

Any release must run against any binary, including ones newer than itself. Never add a
version gate or a refusal to examine something unfamiliar — unknown degrades to "here is what
I could see," never to an error. Published releases are never withdrawn, because comparing
reports across combinations is a supported way to use this tool.

## Practical

- Discuss anything substantial in an issue before building it.
- One concern per PR; say what evidence supports the change.
- New dependencies need a justification in the commit message.
- Apache-2.0. By contributing you agree your work ships under it.
