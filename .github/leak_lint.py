#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""leak-lint — fail the build if internal coordination-layer text reaches a public repo.

This repo is donation-intended and public. It must never carry the vocabulary, ids, or paths
of the private coordination workspace that produces it — a stray bracketed task id, a queue
script name, an internal path, or a sentence naming one person as decision-maker in governance
prose reads, to an outside contributor or downstream adopter, as evidence the "neutral" repo has
an owner steering it from behind the curtain. Four independent rule classes, each catching a
distinct leak shape seen in review:

  1. bracketed internal ids   -- `[` + 3-or-more hyphen-separated lowercase-alnum segments + `]`,
                                  e.g. `[public-repo-internal-leak-lint]`. The 3-segment floor
                                  excludes TOML table headers (`[build-system]`, 2 segments) and
                                  pip extras (`capsule-emit[langchain]`, 1 segment, no brackets
                                  around the whole token). Never fires on markdown inline links
                                  (`[text](url)`), reference links (`[text][ref]` / `[ref]: url`),
                                  or uppercase citation tags (`[RFC2119]`, `[I-D.foo]`) -- those
                                  are excluded structurally: citation tags fail the lowercase-only
                                  character class, and link/reference forms are excluded by what
                                  immediately follows the closing bracket.
  2. ops/lane vocabulary      -- coordination-script and buffer names that only make sense next
                                  to a private queue.
  3. internal paths           -- workspace-relative paths that do not exist outside the private
                                  checkout.
  4. named-decider prose      -- governance text naming one person as the decision authority,
                                  which undercuts the neutrality optic a donatable repo exists to
                                  hold.

Design (same shape as the sibling `hostname_lint.py`):
  - **Exact-text allowlist**, `leak_lint_allowlist.txt` next to this script. Never line numbers
    (they rot the moment a file is edited above the hit) -- the exact stripped line text.
  - **Scans generated artifacts too** (`.txt`, `.xml` I-D outputs), not just `.md` sources -- a
    fix applied to source without a rebuild leaves the leak live in the rendered artifact.
  - **Excludes this script, its allowlist, its own CI workflow, and its own test fixtures by
    filename** -- they legitimately name the patterns they ban, in prose that describes the ban
    or in fixture data that exercises the ban.
  - **Scans the COMMITTED tree** (`git ls-files`), not the working tree -- an untracked file
    reads clean for the wrong reason.

Usage: python leak_lint.py [ROOT=.]
Exit 0 = clean; 1 = leak(s) found (prints file:line:class).
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

SELF_NAMES = {
    "leak_lint.py",
    "leak_lint_allowlist.txt",
    "leak-lint.yml",
    "test_leak_lint.py",
}

SCAN_SUFFIXES = (
    ".py", ".go", ".rs", ".ts", ".js", ".mjs",
    ".md", ".rst", ".txt", ".xml",
    ".toml", ".cfg", ".yml", ".yaml", ".json",
    ".html", ".sh",
)

# Rule 1 -- bracketed internal ids. Lowercase-alnum segments only (excludes uppercase citation
# tags structurally), each segment 2+ chars (excludes a hex regex character class like
# `[0-9a-f]`, which the hyphen-as-range-operator would otherwise fake as 2 hyphen-separated
# segments -- a real task id is always built from meaningful words, never single hex digits),
# 3+ segments (excludes 2-segment TOML headers like [build-system]).
BRACKET_ID = re.compile(r"\[[a-z0-9]{2,}(?:-[a-z0-9]{2,}){2,}\]")

# Rule 2 -- ops/lane vocabulary. Literal substrings, matched case-sensitively as written in the
# spec (avoids false positives like an unrelated product's own "inbox" or "outbox" feature named
# in different casing/context).
OPS_VOCAB = (
    "QUEUE_PROTOCOL",
    "claim.sh",
    "close.sh",
    "decide.sh",
    "outbox",
    "inbox",
    "lane:",
    "worktree",
    "held for EM push",
    "coder-",
    "Needs decision",
    "Do line",
    "R4:",
)

# Rule 3 -- internal paths.
INTERNAL_PATHS = (
    "/dev/asg",
    "_work/",
    "_ops/",
    "action-state-ops",
)

# Rule 4 -- named-decider governance prose.
NAMED_DECIDER = (
    "Steven rules",
    "Steven ratifies",
    "Steven decides",
)


def _tracked_files(root: Path) -> list[Path]:
    out = subprocess.run(
        ["git", "ls-files"], cwd=root, capture_output=True, text=True, check=True
    )
    return [root / p for p in out.stdout.splitlines() if p]


#: A comment line in the allowlist file is `#` followed by whitespace or end-of-line -- NOT
#: just `#` as the first character. A bare `startswith("#")` check would also swallow any
#: allowlisted line that is itself a Markdown heading (e.g. a CHANGELOG.md entry: `### Fixed —
#: ...`), which is exactly the historical-record text this allowlist exists to hold -- silently
#: dropping it from the loaded set and making it impossible to ever allowlist a changelog line.
_COMMENT_LINE = re.compile(r"^#(\s|$)")


def _load_allowlist(root: Path) -> set[str]:
    p = root / ".github" / "leak_lint_allowlist.txt"
    if not p.exists():
        return set()
    return {
        line.rstrip("\n")
        for line in p.read_text().splitlines()
        if line.strip() and not _COMMENT_LINE.match(line.lstrip())
    }


def _has_bracket_id_leak(line: str) -> bool:
    """True if `line` contains a bracketed id that is NOT a markdown link/reference/citation.

    Checked per-match rather than with a single blanket lookahead, because the exempt shapes
    need different context:
      - a pip extra, e.g. `capsule-emit[msft-agent-framework]`: exempt whenever the match is
        immediately preceded by an identifier character (letter/digit/`_`/`-`) with no
        separating whitespace -- that is the `package[extra]` shape, indistinguishable from a
        real id by bracket content alone once the extra name itself has 3+ hyphenated words. A
        real id reference in prose is always set off by whitespace, a paren, a backtick, or
        the start of the line/string before the bracket.
      - inline link `[text](url)` or the first half of `[text][ref]`: exempt whenever the
        match is immediately followed by `(` or `[`, regardless of position in the line.
      - reference-link DEFINITION `[ref]: url`: exempt only when the id-shaped bracket is the
        first thing on the line (only whitespace before it) and is followed by `:` -- that is
        the actual markdown reference-definition shape. An id followed by `:` in the MIDDLE of
        a sentence (e.g. a docstring's opening line naming the id it documents, then a colon)
        is not a reference definition and must still be flagged; a blanket "never follows `:`" rule
        (an earlier version of this check) missed exactly this shape.
      - uppercase citation tags (`[RFC2119]`, `[I-D.foo]`): excluded structurally by
        BRACKET_ID's lowercase-only character class, not handled here.
    """
    for m in BRACKET_ID.finditer(line):
        before = line[m.start() - 1 : m.start()]
        if before and (before.isalnum() or before in "_-"):
            continue
        after = line[m.end() : m.end() + 1]
        if after in "([":
            continue
        if after == ":" and line[: m.start()].strip() == "":
            continue
        return True
    return False


def _classify(line: str) -> list[str]:
    hits = []
    if _has_bracket_id_leak(line):
        hits.append("bracketed-id")
    if any(term in line for term in OPS_VOCAB):
        hits.append("ops-vocab")
    if any(term in line for term in INTERNAL_PATHS):
        hits.append("internal-path")
    if any(term in line for term in NAMED_DECIDER):
        hits.append("named-decider")
    return hits


def _added_lines(root: Path, base: str) -> dict[str, set[int]]:
    """Map each changed file to the set of new-file line numbers this branch ADDED
    relative to ``base`` (merge-base). Used for diff-scoped "no new violations" mode:
    a legacy baseline of hits is tolerated, but any hit on a line this branch touches
    fails. Parses ``git diff --unified=0 base...HEAD`` hunk headers (``@@ -a,b +c,d @@``)
    and counts only ``+`` lines, so a pure deletion or context line never counts."""
    import subprocess

    out = subprocess.run(
        ["git", "-C", str(root), "diff", "--unified=0", "--no-color", f"{base}...HEAD"],
        capture_output=True, text=True, check=True,
    ).stdout
    added: dict[str, set[int]] = {}
    cur: str | None = None
    newno = 0
    for line in out.splitlines():
        if line.startswith("+++ "):
            p = line[4:]
            cur = p[2:] if p.startswith("b/") else (None if p == "/dev/null" else p)
        elif line.startswith("@@"):
            # @@ -a,b +c,d @@  -- c is the first new-file line of this hunk
            plus = line.split("+", 1)[1].split(" ", 1)[0]
            newno = int(plus.split(",", 1)[0])
        elif cur is not None and line.startswith("+") and not line.startswith("+++"):
            added.setdefault(cur, set()).add(newno)
            newno += 1
        elif cur is not None and not line.startswith("-"):
            newno += 1
    return added


def scan(root: Path, changed: dict[str, set[int]] | None = None) -> list[str]:
    allow = _load_allowlist(root)
    hits: list[str] = []
    for f in _tracked_files(root):
        if f.name in SELF_NAMES:
            continue
        if f.suffix not in SCAN_SUFFIXES:
            continue
        rel = str(f.relative_to(root))
        if changed is not None and rel not in changed:
            continue
        try:
            text = f.read_text(errors="ignore")
        except OSError:
            # git ls-files can list a path that no longer exists on disk (deleted-but-staged,
            # a broken symlink) -- not a leak either way, so skip rather than fail the whole
            # scan on an unrelated repo-hygiene issue this lint isn't responsible for catching.
            continue
        for i, line in enumerate(text.splitlines(), start=1):
            if changed is not None and i not in changed[rel]:
                continue
            stripped = line.strip()
            if stripped in allow:
                continue
            classes = _classify(line)
            if classes:
                hits.append(f"{f.relative_to(root)}:{i}:{','.join(classes)}: {stripped}")
    return hits


def main() -> int:
    # Optional: --diff-base <ref> restricts the scan to lines this branch ADDED relative to
    # <ref> ("no new violations" mode -- how a fail-closed lint lands on a repo with a legacy
    # baseline without either blocking on a full cleanup or degrading to advisory warn-mode).
    # Whole-tree remains the default and the goal: flip back to it once the baseline hits zero.
    args = sys.argv[1:]
    diff_base = None
    if "--diff-base" in args:
        i = args.index("--diff-base")
        diff_base = args[i + 1]
        del args[i : i + 2]
    root = Path(args[0] if args else ".")
    changed = _added_lines(root, diff_base) if diff_base else None
    hits = scan(root, changed)
    scope = f"lines added since {diff_base}" if diff_base else "the committed tree"
    if hits:
        print(f"leak-lint: {len(hits)} internal-leak hit(s) found in {scope}.")
        print(
            "If a hit is a genuine historical record (not live drift), add its exact stripped "
            "line text to .github/leak_lint_allowlist.txt. Otherwise, fix it -- an allowlist "
            "seeded with a real leak teaches the next person the lint is advisory."
        )
        for h in hits:
            print(" ", h)
        return 1
    print(f"leak-lint: clean ({scope}).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
