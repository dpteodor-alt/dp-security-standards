#!/usr/bin/env python3
"""DP security gate: merge PHPCS + Semgrep findings, apply the baseline, decide pass/fail.

Usage:
  dp-gate.py check    --root . --phpcs phpcs.json --semgrep semgrep.json [--baseline FILE] [--fail-on-warnings]
  dp-gate.py baseline --root . --phpcs phpcs.json --semgrep semgrep.json  --baseline FILE

A finding is identified by a fingerprint that does not depend on its line number:
  sha1( tool | rule | path | normalized source line | occurrence index )
so moving code up or down does not create "new" findings, while a new vulnerable line does.

check:    new ERROR findings fail (exit 1). New warnings fail only with --fail-on-warnings.
          Baselined findings are listed as known. Prints GitHub annotations and a step summary.
baseline: writes every current finding (errors and warnings) to the baseline file.

Exit codes: 0 pass, 1 new blocking findings, 2 usage or input error.
"""

import argparse
import datetime
import hashlib
import json
import os
import sys

BASELINE_VERSION = 1


def read_json(path, tool):
    if not path:
        return None
    try:
        with open(path, encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, ValueError) as exc:
        sys.stderr.write("dp-gate: cannot read %s report %s: %s\n" % (tool, path, exc))
        sys.exit(2)


def rel_path(root, path):
    absolute = path if os.path.isabs(path) else os.path.abspath(path)
    return os.path.relpath(absolute, root).replace(os.sep, "/")


def collect(root, phpcs_path, semgrep_path):
    findings = []
    phpcs = read_json(phpcs_path, "PHPCS")
    if phpcs is not None:
        for path, data in phpcs.get("files", {}).items():
            for msg in data.get("messages", []):
                findings.append({
                    "tool": "phpcs",
                    "rule": msg["source"],
                    "path": rel_path(root, path),
                    "line": int(msg["line"]),
                    "severity": "error" if msg["type"].upper() == "ERROR" else "warning",
                    "message": msg["message"],
                })
    semgrep = read_json(semgrep_path, "Semgrep")
    if semgrep is not None:
        if semgrep.get("errors"):
            for err in semgrep["errors"]:
                level = str(err.get("level", "error")).lower()
                text = str(err.get("message", err))[:300]
                sys.stderr.write("dp-gate: semgrep %s: %s\n" % (level, text))
                # A rule that failed to parse means the gate is not checking what it claims.
                if "rule" in str(err.get("type", "")).lower():
                    sys.exit(2)
        for res in semgrep.get("results", []):
            sev = res["extra"].get("severity", "ERROR").upper()
            findings.append({
                "tool": "semgrep",
                "rule": res["check_id"].split(".")[-1],
                "path": rel_path(root, res["path"]),
                "line": int(res["start"]["line"]),
                "severity": "error" if sev == "ERROR" else "warning",
                "message": " ".join(res["extra"].get("message", "").split()),
            })
    return findings


def source_line(root, path, line, cache):
    if path not in cache:
        try:
            with open(os.path.join(root, path), encoding="utf-8", errors="replace") as handle:
                cache[path] = handle.read().splitlines()
        except OSError:
            cache[path] = []
    lines = cache[path]
    text = lines[line - 1] if 0 < line <= len(lines) else ""
    return " ".join(text.split())


def fingerprint(root, findings):
    cache = {}
    seen = {}
    for f in sorted(findings, key=lambda x: (x["path"], x["line"], x["tool"], x["rule"])):
        key = "|".join((f["tool"], f["rule"], f["path"], source_line(root, f["path"], f["line"], cache)))
        index = seen.get(key, 0)
        seen[key] = index + 1
        f["fingerprint"] = hashlib.sha1(("%s|%d" % (key, index)).encode("utf-8")).hexdigest()
    return findings


def load_baseline(path):
    if not path or not os.path.exists(path):
        return {}
    with open(path, encoding="utf-8") as handle:
        data = json.load(handle)
    if data.get("version") != BASELINE_VERSION:
        sys.stderr.write("dp-gate: unsupported baseline version in %s\n" % path)
        sys.exit(2)
    return {item["fingerprint"]: item for item in data.get("findings", [])}


def escape_annotation(text):
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def cmd_baseline(args, findings):
    items = [
        {k: f[k] for k in ("fingerprint", "tool", "rule", "path", "line", "severity")}
        for f in sorted(findings, key=lambda x: (x["path"], x["line"], x["rule"]))
    ]
    data = {
        "version": BASELINE_VERSION,
        "created": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "note": "Known findings at adoption time. Fix them over time; never add new ones by hand.",
        "findings": items,
    }
    directory = os.path.dirname(args.baseline)
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(args.baseline, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=1, sort_keys=False)
        handle.write("\n")
    errors = len([f for f in findings if f["severity"] == "error"])
    print("dp-gate: wrote %d finding(s) (%d error, %d warning) to %s" % (
        len(items), errors, len(items) - errors, args.baseline))
    return 0


def cmd_check(args, findings):
    baseline = load_baseline(args.baseline)
    current = {f["fingerprint"] for f in findings}
    new = [f for f in findings if f["fingerprint"] not in baseline]
    known = [f for f in findings if f["fingerprint"] in baseline]
    fixed = [b for fp, b in baseline.items() if fp not in current]
    blocking = [f for f in new if f["severity"] == "error" or args.fail_on_warnings]

    in_actions = os.environ.get("GITHUB_ACTIONS") == "true"
    for f in sorted(new, key=lambda x: (x["path"], x["line"])):
        level = "error" if f in blocking else "warning"
        label = "%s %s" % (f["tool"], f["rule"])
        if in_actions:
            print("::%s file=%s,line=%d,title=%s::%s" % (
                level, f["path"], f["line"], escape_annotation(label), escape_annotation(f["message"])))
        else:
            print("%s:%d: [%s] %s: %s" % (f["path"], f["line"], level.upper(), label, f["message"]))

    summary = [
        "## DP security gate",
        "",
        "| | Errors | Warnings |",
        "| --- | ---: | ---: |",
        "| New | %d | %d |" % (len([f for f in new if f["severity"] == "error"]), len([f for f in new if f["severity"] == "warning"])),
        "| Known (baseline) | %d | %d |" % (len([f for f in known if f["severity"] == "error"]), len([f for f in known if f["severity"] == "warning"])),
        "| Fixed since baseline | %d | %d |" % (len([b for b in fixed if b["severity"] == "error"]), len([b for b in fixed if b["severity"] == "warning"])),
        "",
    ]
    if new:
        summary += ["| File | Line | Severity | Rule |", "| --- | ---: | --- | --- |"]
        for f in sorted(new, key=lambda x: (x["path"], x["line"]))[:200]:
            summary.append("| `%s` | %d | %s | `%s` |" % (f["path"], f["line"], f["severity"], f["rule"]))
        summary.append("")
    if fixed:
        summary.append("%d baselined finding(s) no longer occur: regenerate the baseline to lock in the progress." % len(fixed))
    summary.append("**Result: %s**" % ("FAIL - %d new blocking finding(s)" % len(blocking) if blocking else "PASS"))
    text = "\n".join(summary) + "\n"
    step_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if step_summary:
        with open(step_summary, "a", encoding="utf-8") as handle:
            handle.write(text)
    print(text)
    return 1 if blocking else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("command", choices=("check", "baseline"))
    parser.add_argument("--root", default=".")
    parser.add_argument("--phpcs")
    parser.add_argument("--semgrep")
    parser.add_argument("--baseline", default=".dp-security/baseline.json")
    parser.add_argument("--fail-on-warnings", action="store_true")
    args = parser.parse_args()
    if not args.phpcs and not args.semgrep:
        parser.error("give --phpcs and/or --semgrep")
    root = os.path.abspath(args.root)
    findings = fingerprint(root, collect(root, args.phpcs, args.semgrep))
    if args.command == "baseline":
        return cmd_baseline(args, findings)
    return cmd_check(args, findings)


if __name__ == "__main__":
    sys.exit(main())
