#!/usr/bin/env python3
"""Design-note check (benchmark standard, requirement 11).

The spec asks for a one-page design note, written before coding, covering
the threat model, where keys live and how deletion actually deletes, plus a
justified choice between client-side and server-side encryption.

This script checks what a machine can check and prints the evidence an
organizer needs to judge the rest:

  1. DESIGN.md exists at the repo root (any case, or under docs/).
  2. It fits on one page: at most --max-words words (default 1000).
  3. A "threat model" section with real content.
  4. A "keys" section with real content.
  5. A "deletion" section with real content.
  6. The crypto choice is named (client-side or server-side) with a reason
     in the same paragraph. The matching line is printed for a human.
  7. Written before code: in git history, DESIGN.md was first committed no
     later than the first commit that added a non-documentation file.
     Skipped (and reported) when the repo is not a git repository.

Usage:  python tests/check_design.py [REPO_DIR] [--max-words N]
Exit code 0 when every check passes (a skipped check does not fail).
"""
import argparse
import re
import subprocess
import sys
from pathlib import Path

MIN_SECTION_WORDS = 40
DOC_SUFFIXES = {".md", ".txt", ".rst", ".adoc", ".pdf", ".png", ".jpg", ".svg"}
DOC_NAMES = {"license", "license.md", ".gitignore", ".gitattributes"}

SECTIONS = {
    "threat model": re.compile(r"threat", re.I),
    "where keys live": re.compile(r"\bkeys?\b|key management|secrets? storage", re.I),
    "how deletion deletes": re.compile(r"delet|eras|destroy|purg", re.I),
}
CHOICE = re.compile(r"\b(client|server)[- ]side\b", re.I)
REASON = re.compile(r"\b(because|since|so that|so\b|instead|trade-?off|justif|therefore|which means)", re.I)


def find_note(repo: Path):
    for folder in (repo, repo / "docs"):
        if folder.is_dir():
            for p in folder.iterdir():
                if p.is_file() and p.name.lower() == "design.md":
                    return p
    return None


def sections(text: str):
    """Yield (heading, body) pairs; a body runs to the next heading of the same or higher level."""
    lines = text.splitlines()
    heads = [(i, len(m.group(1)), m.group(2).strip())
             for i, line in enumerate(lines)
             if (m := re.match(r"^(#{1,6})\s+(.*)", line))]
    for n, (i, level, title) in enumerate(heads):
        end = next((j for j, lv, _ in heads[n + 1:] if lv <= level), len(lines))
        yield title, "\n".join(lines[i + 1:end])


def words(s: str) -> int:
    return len(re.findall(r"[A-Za-z0-9][\w'-]*", s))


def git(repo: Path, *args):
    r = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True)
    return r.stdout.strip() if r.returncode == 0 else None


def written_before_code(repo: Path, note: Path):
    if git(repo, "rev-parse", "--is-inside-work-tree") != "true":
        return None, "not a git repository, cannot prove order"
    rel = note.relative_to(repo).as_posix()
    note_times = git(repo, "log", "--diff-filter=A", "--format=%at", "--", rel)
    if not note_times:
        return False, f"{rel} is not committed"
    note_at = int(note_times.splitlines()[-1])
    log = git(repo, "log", "--reverse", "--diff-filter=A", "--name-only", "--format=@%at")
    code_at, code_file = None, None
    stamp = None
    for line in (log or "").splitlines():
        if line.startswith("@"):
            stamp = int(line[1:])
        elif line and stamp is not None:
            p = Path(line)
            if p.suffix.lower() not in DOC_SUFFIXES and p.name.lower() not in DOC_NAMES:
                code_at, code_file = stamp, line
                break
    if code_at is None:
        return True, "no code committed yet"
    ok = note_at <= code_at
    return ok, f"design note committed {'before' if ok else 'after'} first code file ({code_file})"


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("repo", nargs="?", default=".")
    ap.add_argument("--max-words", type=int, default=1000)
    args = ap.parse_args()
    repo = Path(args.repo).resolve()

    results = []

    def report(name, ok, detail=""):
        tag = {True: "PASS", False: "FAIL", None: "SKIP"}[ok]
        results.append(ok)
        print(f"[{tag}] {name}" + (f": {detail}" if detail else ""))

    note = find_note(repo)
    report("design note exists", note is not None, str(note.relative_to(repo)) if note else "no DESIGN.md")
    if note is None:
        return 1
    text = note.read_text(encoding="utf-8", errors="replace")

    total = words(text)
    report("fits on one page", total <= args.max_words, f"{total} words, limit {args.max_words}")

    found = list(sections(text))
    for label, pattern in SECTIONS.items():
        hit = next(((t, b) for t, b in found if pattern.search(t)), None)
        if hit is None:
            report(f"section: {label}", False, "no heading matches")
        else:
            n = words(hit[1])
            report(f"section: {label}", n >= MIN_SECTION_WORDS, f'"{hit[0]}", {n} words')

    paragraphs = re.split(r"\n\s*\n|\n(?=\s*[-*] )", text)
    choice = next((p for p in paragraphs if CHOICE.search(p) and REASON.search(p)), None)
    if choice:
        line = " ".join(choice.split())
        report("crypto choice named with a reason", True, (line[:200] + "...") if len(line) > 200 else line)
    else:
        report("crypto choice named with a reason", False, "no paragraph names client-side or server-side with a reason")

    ok, detail = written_before_code(repo, note)
    report("written before code", ok, detail)

    failed = results.count(False)
    print(f"\n{results.count(True)} passed, {failed} failed, {results.count(None)} skipped")
    print("Organizer: read the crypto-choice line above and confirm the reason actually justifies the choice.")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
