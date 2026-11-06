#!/usr/bin/env python3
"""Check tool output against the fixture expectations.

Rules for every tests/fixtures/DP-SEC-NNN/ directory:

* bad.php  - each line ending in "// expect: <id>[, <id> ...]" must produce a finding of
             that rule on that line (Semgrep rule id, or PHPCS sniff code / prefix).
             A finding of the same rule family on an unmarked line is a failure too,
             so fixtures stay exact.
* good.php - must produce no finding at all, from any rule of either tool.

Exit code 0 when every expectation holds, 1 otherwise.
"""

import argparse
import json
import os
import re
import sys

# PHPCS sniffs that implement a DP-SEC rule. Semgrep rules carry the ID in their name.
PHPCS_FAMILIES = {
    "DP-SEC-009": ("WordPress.DB.PreparedSQL",),
    "DP-SEC-010": ("WordPress.Security.EscapeOutput",),
    "DP-SEC-011": ("WordPress.Security.NonceVerification",),
    "DP-SEC-012": ("WordPress.Security.ValidatedSanitizedInput",),
    "DP-SEC-019": ("WordPress.Security.SafeRedirect",),
}

EXPECT_RE = re.compile(r"expect:\s*([A-Za-z0-9_.,\-\s]+?)\s*$")


def load_findings(root, phpcs_path, semgrep_path):
    findings = []
    with open(phpcs_path, encoding="utf-8") as handle:
        phpcs = json.load(handle)
    for path, data in phpcs.get("files", {}).items():
        rel = os.path.relpath(os.path.join(root, path) if not os.path.isabs(path) else path, root)
        for msg in data.get("messages", []):
            findings.append({
                "tool": "phpcs",
                "rule": msg["source"],
                "path": rel,
                "line": msg["line"],
                "severity": msg["type"].lower(),
                "message": msg["message"],
            })
    with open(semgrep_path, encoding="utf-8") as handle:
        semgrep = json.load(handle)
    errors = semgrep.get("errors", [])
    for res in semgrep.get("results", []):
        path = res["path"]
        rel = os.path.relpath(path if os.path.isabs(path) else os.path.join(os.getcwd(), path), root)
        findings.append({
            "tool": "semgrep",
            "rule": res["check_id"].split(".")[-1],
            "path": rel,
            "line": res["start"]["line"],
            "severity": res["extra"]["severity"].lower(),
            "message": res["extra"]["message"],
        })
    return findings, errors


def family_of(fixture_id, finding):
    """True if the finding belongs to the rule tested by this fixture directory."""
    if finding["tool"] == "semgrep":
        return finding["rule"].lower().startswith(fixture_id.lower())
    return finding["rule"].startswith(PHPCS_FAMILIES.get(fixture_id, ("\0",)))


def matches(marker, finding):
    if finding["tool"] == "semgrep":
        return finding["rule"].lower() == marker.lower()
    return finding["rule"] == marker or finding["rule"].startswith(marker + ".")


def parse_markers(path):
    markers = []
    with open(path, encoding="utf-8") as handle:
        for number, text in enumerate(handle, start=1):
            if "expect:" not in text:
                continue
            match = EXPECT_RE.search(text)
            if match:
                for item in match.group(1).split(","):
                    item = item.strip().rstrip(".")
                    if item:
                        markers.append((number, item))
    return markers


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True)
    parser.add_argument("--phpcs", required=True)
    parser.add_argument("--semgrep", required=True)
    args = parser.parse_args()

    root = os.path.abspath(args.root)
    findings, semgrep_errors = load_findings(root, args.phpcs, args.semgrep)
    failures = []
    rows = []

    if semgrep_errors:
        for err in semgrep_errors:
            failures.append("semgrep error: %s" % err.get("message", err)[:400])

    fixtures_dir = os.path.join(root, "tests", "fixtures")
    for fixture_id in sorted(os.listdir(fixtures_dir)):
        base = os.path.join(fixtures_dir, fixture_id)
        if not os.path.isdir(base):
            continue
        for kind in ("bad", "good"):
            file_path = os.path.join(base, kind + ".php")
            rel = os.path.relpath(file_path, root)
            if not os.path.exists(file_path):
                failures.append("%s: missing %s.php" % (fixture_id, kind))
                continue
            in_file = [f for f in findings if f["path"] == rel]
            if kind == "good":
                status = "PASS" if not in_file else "FAIL"
                for f in in_file:
                    failures.append("%s:%d good.php must be silent, got %s (%s)" % (rel, f["line"], f["rule"], f["severity"]))
                rows.append((fixture_id, kind, "silent", "%d finding(s)" % len(in_file), status))
                continue

            markers = parse_markers(file_path)
            ok = True
            if not markers:
                failures.append("%s: bad.php has no expect markers" % rel)
                ok = False
            used = set()
            for line, marker in markers:
                hit = [f for f in in_file if f["line"] == line and matches(marker, f)]
                if not hit:
                    failures.append("%s:%d expected %s, got nothing" % (rel, line, marker))
                    ok = False
                for f in hit:
                    used.add(id(f))
            for f in in_file:
                if family_of(fixture_id, f) and id(f) not in used:
                    failures.append("%s:%d unexpected %s (%s) - add a marker or fix the rule" % (rel, f["line"], f["rule"], f["severity"]))
                    ok = False
            fired = sorted({f["rule"] for f in in_file if id(f) in used})
            rows.append((fixture_id, kind, "%d marker(s)" % len(markers), ", ".join(fired) or "-", "PASS" if ok else "FAIL"))

    width = max(len(r[3]) for r in rows) if rows else 10
    print("%-11s %-5s %-12s %-*s %s" % ("Fixture", "File", "Expected", width, "Fired", "Result"))
    for row in rows:
        print("%-11s %-5s %-12s %-*s %s" % (row[0], row[1], row[2], width, row[3], row[4]))
    print()
    print("Findings total: %d (phpcs %d, semgrep %d)" % (
        len(findings),
        len([f for f in findings if f["tool"] == "phpcs"]),
        len([f for f in findings if f["tool"] == "semgrep"]),
    ))
    if failures:
        print("\nFAILURES (%d):" % len(failures))
        for item in failures:
            print("  - " + item)
        return 1
    print("All fixtures behave as expected.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
