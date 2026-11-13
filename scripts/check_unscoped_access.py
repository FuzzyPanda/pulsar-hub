#!/usr/bin/env python
"""Fail if code reaches across organisations without saying why.

Organisation isolation is a security boundary (CLAUDE.md rule 1). Business rows are read through
the organisation-scoped default manager. The ways around it are few and each one must carry a
comment, on the same line or the line above, of the form:

    # unscoped: <reason>

This script finds every way around it in `hub/` and exits 1 if one has no reason. It runs in CI
(job "lint") and in the test suite.

What counts:
  .all_organisations          the cross-organisation manager
  ._base_manager / ._default_manager   Django's internal managers
  .raw( / RawSQL( / .extra(   raw SQL through the ORM
  connection.cursor / connections[   raw SQL around the ORM
"""

import re
import sys
import tokenize
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PATTERNS = [
    re.compile(r"\.all_organisations\b"),
    re.compile(r"\._base_manager\b"),
    re.compile(r"\._default_manager\b"),
    re.compile(r"\.raw\("),
    re.compile(r"RawSQL\("),
    re.compile(r"\.extra\("),
    # Tokens are joined without spaces before matching, so no leading word boundary here.
    re.compile(r"connection\.cursor\b"),
    re.compile(r"connections\["),
]
PRAGMA = re.compile(r"#\s*unscoped:\s*\S.{7,}")
# The files that define the mechanism itself.
EXEMPT = {
    "hub/organisations/scoping.py",
    "hub/organisations/checks.py",
}


def code_and_comments(path: Path) -> tuple[dict[int, str], dict[int, str]]:
    """Per line: the code with strings and comments removed, and the comment text."""
    code: dict[int, list[str]] = {}
    comments: dict[int, str] = {}
    with tokenize.open(path) as handle:
        for token in tokenize.generate_tokens(handle.readline):
            line = token.start[0]
            if token.type == tokenize.COMMENT:
                comments[line] = token.string
            elif token.type in (tokenize.STRING, tokenize.FSTRING_MIDDLE):
                continue
            elif token.type not in (tokenize.NL, tokenize.NEWLINE, tokenize.INDENT, tokenize.DEDENT):
                code.setdefault(line, []).append(token.string)
    return {line: "".join(parts) for line, parts in code.items()}, comments


def violations(root: Path = ROOT) -> list[str]:
    found = []
    for path in sorted((root / "hub").rglob("*.py")):
        relative = path.relative_to(root).as_posix()
        if "/migrations/" in relative or relative in EXEMPT:
            continue
        code, comments = code_and_comments(path)
        for line, text in sorted(code.items()):
            if not any(pattern.search(text) for pattern in PATTERNS):
                continue
            # The reason may sit on the same line, the line above, or (for a call that the
            # formatter wrapped) the line below.
            nearby = (comments.get(line, ""), comments.get(line - 1, ""), comments.get(line + 1, ""))
            if not any(PRAGMA.search(comment) for comment in nearby):
                found.append(f"{relative}:{line}: cross-organisation access without `# unscoped: <reason>`")
    return found


def main() -> int:
    found = violations()
    for item in found:
        print(item)
    if found:
        print(f"\n{len(found)} unexplained cross-organisation access(es). See scripts/check_unscoped_access.py.")
        return 1
    print("check_unscoped_access: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
