#!/usr/bin/env python3
"""
apply_script_patch.py -- apply a Falco packaging diff to RENDERED maintainer scripts.

Falco embeds scripts/packaging/functions.sh.in into every maintainer script
at CMake configure time (@FALCO_PACKAGE_FUNCTIONS@), and an .rpm keeps all of
its scriptlets in one spec. So a one-hunk fix to functions.sh.in appears once
per script, several times in an rpm spec. `patch` would fix only the first
copy; this replaces every copy and says how many it found.

    apply_script_patch.py FIX.patch FILE...     edit the files in place
    apply_script_patch.py FIX.patch -           stdin to stdout (rpmrebuild filter)

Each hunk is read as (context + removed lines) -> (context + added lines).
A file that embeds the functions must contain every hunk's old block, or
the build stops: a fix that no longer matches the release is not this fix.
Files that do not embed the functions are left alone.
"""

from __future__ import annotations

import sys
from pathlib import Path


def hunks(patch_text: str) -> list[tuple[str, str]]:
    out, old, new, inside = [], [], [], False
    for line in patch_text.splitlines():
        if line.startswith("@@"):
            if inside:
                out.append(("\n".join(old) + "\n", "\n".join(new) + "\n"))
            old, new, inside = [], [], True
        elif not inside or line.startswith(("diff ", "index ", "--- ", "+++ ")):
            continue
        elif line.startswith("-"):
            old.append(line[1:])
        elif line.startswith("+"):
            new.append(line[1:])
        elif line.startswith("\\"):
            continue
        else:
            text = line[1:] if line.startswith(" ") else line
            old.append(text)
            new.append(text)
    if inside:
        out.append(("\n".join(old) + "\n", "\n".join(new) + "\n"))
    return out


def apply(text: str, patch_hunks: list[tuple[str, str]], where: str) -> tuple[str, int]:
    """(patched text, copies patched). 0 copies means the file does not embed it."""
    counts = [text.count(old) for old, _ in patch_hunks]
    if not any(counts):
        # An rpm spec (rpmrebuild's view of the scriptlets) writes a literal
        # % as %%, e.g. the comment "before %post" in package_driver_version.
        escaped = [(old.replace("%", "%%"), new.replace("%", "%%")) for old, new in patch_hunks]
        if any(text.count(old) for old, _ in escaped):
            return apply(text, escaped, where)
        return text, 0
    if len(set(counts)) != 1:
        raise SystemExit(f"{where}: hunks matched unevenly {counts}; the fix does not fit this release")
    for old, new in patch_hunks:
        text = text.replace(old, new)
    return text, counts[0]


def main() -> int:
    if len(sys.argv) < 3:
        print(__doc__, file=sys.stderr)
        return 2
    patch_hunks = hunks(Path(sys.argv[1]).read_text())
    if not patch_hunks:
        raise SystemExit(f"{sys.argv[1]}: no hunks")
    if sys.argv[2:] == ["-"]:
        text, n = apply(sys.stdin.read(), patch_hunks, "stdin")
        if not n:
            raise SystemExit("stdin: no copy of the patched code")
        sys.stdout.write(text)
        print(f"stdin: patched {n} copies", file=sys.stderr)
        return 0
    total = 0
    for name in sys.argv[2:]:
        path = Path(name)
        text, n = apply(path.read_text(), patch_hunks, name)
        if n:
            path.write_text(text)
        print(f"{name}: patched {n} copies", file=sys.stderr)
        total += n
    if not total:
        raise SystemExit("no file embeds the patched code")
    return 0


if __name__ == "__main__":
    sys.exit(main())
