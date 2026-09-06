# Pet Passport — project contract

Read by Claude Code on every session. This file governs *how* work is done here.
`docs/design.md` governs *what* is being built and why, and is not restated here — read it
first, every time, before proposing anything.

## 1. The refusals are the product

`docs/design.md` has a **Non-goals** section. Those entries are not unfinished work, not
gaps, and not a backlog. They are the design.

Each one will eventually seem worth adding, with a reasonable argument, because each
individually is a small convenience: a `--json` flag for scripting, a one-line summary so
readers know what matters, a severity column, a shareable badge. Together they reconstitute
the authority this project declines to hold — a tool that issues verdicts it cannot stand
behind. Adding any of them is a design change requiring an explicit decision, never an
incidental improvement made while doing something else.

If a task seems to require one of them, that is a signal to stop and ask, not to proceed.

## 2. Leakage rule

This repository is public. It is developed alongside a **closed-source** desktop pet, and
sessions working here may carry context from that codebase.

**Nothing from that codebase enters this one.** Not source, not file or module names, not
the specific API symbols it calls, not its architecture, and above all not any unreleased
defect or weakness in it. Publishing a closed product's flaws in a public repository
discloses them to everyone who reads it.

Illustrations in documentation must be written generically — describe a *kind* of program
and a *kind* of behavior, never a real product's implementation. Before committing, grep the
diff for identifying terms and satisfy yourself that nothing crossed over.

This rule is one-directional and absolute: it does not matter that the two projects are
related, that the detail seems harmless, or that it would make an example clearer.

## 3. Stack: Rust with goblin

Pet Passport is implemented in Rust, using the `goblin` crate for PE parsing. It is a single,
self-contained binary with no runtime for a user to install. This fits the trust model: a
person can fetch a fresh copy themselves and run it, without first accepting a separate
runtime installation or a tool bundled by the party being examined. `goblin` was selected in
the prior assessment as a mature, small PE-parsing crate.

## 4. The mapping table is the credibility

Whatever engine reads binaries, the artifact that determines whether this tool is trusted is
the published mapping from observed evidence to the words used to describe it. It must be
mechanical, versioned, and auditable by someone who disagrees with a specific call. Any
change to how an observation is worded is a change to that table, not a copy edit.

It follows that the mapping lives in a data file in this repository, not in string literals
scattered through the code — a table nobody can read as a table is not auditable.

Note the distinction this creates, because it is easy to misread §1 as forbidding it: a
structured, versioned schema for that **input** data file is correct and wanted. The
prohibition is on a schema for report **output**. Configuration the project publishes and
stands behind is the opposite of a machine-readable result format that invites others to
build gates on it.

## 5. Rules for the agent

1. Read `docs/design.md` before proposing or implementing any feature.
2. Never add a verdict, score, severity ranking, badge, summary line, output schema
   (including `--json`), or aggregated results service. See §1.
3. Never state or imply that anything is safe — including by a reassuring absence of output.
4. Report what could not be examined. Silence about a blind spot is the one way a purely
   descriptive tool still misleads.
5. Prefer the specific observation over any summary of it. Name mechanisms, not intent.
6. Obey §2. Grep the diff before committing.
7. Do not add a dependency without stating why in the commit message.
8. When a task is ambiguous, ask one question; do not guess.
9. Open questions in `docs/design.md` are open. Do not settle one by implementing a side that
   suits the current task — raise it.
