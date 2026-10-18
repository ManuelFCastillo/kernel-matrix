#!/usr/bin/env python3
"""
apply_script_patch.py -- apply a Falco packaging diff to RENDERED maintainer scripts.

Falco embeds scripts/packaging/functions.sh.in into every maintainer script
at CMake configure time (@FALCO_PACKAGE_FUNCTIONS@), and an .rpm keeps all of
its scriptlets in one spec. So a one-hunk fix to functions.sh.in appears once
per script, several times in an rpm spec. `patch` would fix only the first
copy; this replaces every copy and says how many it found.

    apply_script_patch.py [--format deb|rpm] FIX.patch FILE...   edit the files in place
    apply_script_patch.py [--format deb|rpm] FIX.patch -         stdin to stdout (rpmrebuild filter)

Each hunk is read as (context + removed lines) -> (context + added lines),
grouped by the source file it changes. Within a file, a group's hunks must
match equally often, or the build stops: a fix that only half matches the
release is not this fix. A file without any of a group's code is left alone.

Every group must be applied somewhere. With --format, a group for the other
format's scripts (scripts/debian/... in an rpm, scripts/rpm/... in a deb) is
skipped, so one patch serves both builds. Skipped, not merely optional: the
deb postinst and the rpm %post share code, so the deb hunk would otherwise
patch the rpm and leave its own hunk nothing to match.
"""

from __future__ import annotations

import sys
from pathlib import Path

OTHER_FORMAT = {"deb": "scripts/rpm/", "rpm": "scripts/debian/"}


def hunks(patch_text: str) -> dict[str, list[tuple[str, str]]]:
    """{source path: [(old, new), ...]} in patch order."""
    out: dict[str, list[tuple[str, str]]] = {}
    path, old, new, inside = "-", [], [], False

    def close():
        if inside:
            out.setdefault(path, []).append(("\n".join(old) + "\n", "\n".join(new) + "\n"))

    for line in patch_text.splitlines():
        if line.startswith("diff "):
            close()
            inside = False
        elif line.startswith("+++ ") and not inside:
            path = line[4:].removeprefix("b/").strip()
        elif line.startswith("@@"):
            close()
            old, new, inside = [], [], True
        elif not inside or line.startswith(("index ", "--- ")):
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
    close()
    return out


def apply_group(text: str, group: list[tuple[str, str]], where: str) -> tuple[str, int]:
    """(patched text, copies patched). 0 copies means the file does not embed it."""
    counts = [text.count(old) for old, _ in group]
    if not any(counts):
        # An rpm spec (rpmrebuild's view of the scriptlets) writes a literal
        # % as %%, e.g. the comment "before %post" in package_driver_version.
        escaped = [(old.replace("%", "%%"), new.replace("%", "%%")) for old, new in group]
        if any(text.count(old) for old, _ in escaped):
            return apply_group(text, escaped, where)
        return text, 0
    if len(set(counts)) != 1:
        raise SystemExit(f"{where}: hunks matched unevenly {counts}; the fix does not fit this release")
    for old, new in group:
        text = text.replace(old, new)
    return text, counts[0]


def apply(text: str, groups: dict[str, list[tuple[str, str]]], where: str) -> tuple[str, dict[str, int]]:
    copies = {}
    for path, group in groups.items():
        text, copies[path] = apply_group(text, group, f"{where} ({path})")
    return text, copies


def expected(groups: dict[str, list], fmt: str | None) -> list[str]:
    return [p for p in groups if not (fmt and p.startswith(OTHER_FORMAT[fmt]))]


def main(argv: list[str]) -> int:
    fmt = None
    if argv[:1] == ["--format"]:
        if len(argv) < 2 or argv[1] not in OTHER_FORMAT:
            print(__doc__, file=sys.stderr)
            return 2
        fmt, argv = argv[1], argv[2:]
    if len(argv) < 2:
        print(__doc__, file=sys.stderr)
        return 2
    groups = hunks(Path(argv[0]).read_text())
    if not groups:
        raise SystemExit(f"{argv[0]}: no hunks")
    groups = {p: groups[p] for p in expected(groups, fmt)}
    total = dict.fromkeys(groups, 0)
    if argv[1:] == ["-"]:
        text, copies = apply(sys.stdin.read(), groups, "stdin")
        sys.stdout.write(text)
        for path, n in copies.items():
            print(f"stdin: {path}: patched {n} copies", file=sys.stderr)
            total[path] += n
    else:
        for name in argv[1:]:
            path = Path(name)
            text, copies = apply(path.read_text(), groups, name)
            if any(copies.values()):
                path.write_text(text)
            for src, n in copies.items():
                print(f"{name}: {src}: patched {n} copies", file=sys.stderr)
                total[src] += n
    missing = [p for p in groups if not total[p]]
    if missing:
        raise SystemExit(f"no copy of the patched code from {', '.join(missing)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
