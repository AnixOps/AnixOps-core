#!/usr/bin/env python3
"""Action pinning rule for the workflows and composite actions (CI policy-fast, release policy gate).

Every action a workflow, reusable workflow or composite action uses is either local (./...) or pinned to a full
40-digit commit SHA with its release tag in a comment ("uses: owner/repo@<sha> # v1.2.3"). A moved tag of an
upstream action then cannot run new code in a job that publishes, signs or attests a release; Dependabot
(.github/dependabot.yml) proposes the updates as reviewed pull requests. Docker actions are refused.

Same rule as the client repository's .github/scripts/workflow_policy.py.

Usage: workflow_policy.py [--self-test] [ROOT]
"""

import os
import re
import sys

USES = re.compile(r"^\s*(?:-\s+)?uses:\s*(\S+)\s*(#.*)?$")
PINNED = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.\-/]+@[0-9a-f]{40}$")
TAG_COMMENT = re.compile(r"^#\s*v\d+(\.\d+)*\S*$")


def check_uses(path, text):
    errors = []
    for number, line in enumerate(text.splitlines(), 1):
        match = USES.match(line)
        if not match:
            continue
        target, comment = match.group(1).strip("'\""), (match.group(2) or "").strip()
        if target.startswith("./"):
            continue
        if target.startswith("docker://"):
            errors.append(f"{path}:{number}: docker actions are not allowed: {target}")
        elif not PINNED.match(target):
            errors.append(f"{path}:{number}: {target} is not pinned to a full commit SHA")
        elif not TAG_COMMENT.match(comment):
            errors.append(f"{path}:{number}: {target} needs its release tag in a comment, e.g. '# v4.2.0'")
    return errors


def workflow_files(root):
    found = []
    for base in (os.path.join(root, ".github", "workflows"), os.path.join(root, ".github", "actions")):
        for directory, _, names in os.walk(base):
            for name in names:
                if name.endswith((".yml", ".yaml")):
                    found.append(os.path.join(directory, name))
    return sorted(found)


def check(root):
    files = workflow_files(root)
    if not files:
        return [f"{root}: no workflow files found"]
    errors = []
    for path in files:
        with open(path, encoding="utf-8") as handle:
            errors += check_uses(os.path.relpath(path, root), handle.read())
    return errors


def self_test():
    sha = "a" * 40
    good = f"""
steps:
  - uses: actions/checkout@{sha} # v7.0.1
  - name: x
    uses: owner/repo/sub/path@{sha}  # v2
  - uses: ./.github/actions/local
jobs:
  reuse:
    uses: ./.github/workflows/capture-gates.yml
"""
    assert check_uses("good.yml", good) == [], check_uses("good.yml", good)
    bad = {
        "  - uses: actions/checkout@v4": "not pinned",
        "  - uses: actions/attest@v4.2.2 # v4.2.2": "not pinned",
        f"  - uses: actions/checkout@{sha[:39]} # v7": "not pinned",
        f"  - uses: actions/checkout@{sha.upper()} # v7": "not pinned",
        "  - uses: actions/download-artifact@main": "not pinned",
        f"  - uses: actions/checkout@{sha}": "release tag",
        f"  - uses: actions/checkout@{sha} # latest": "release tag",
        "  - uses: docker://alpine:3": "docker",
        "    uses: org/repo/.github/workflows/release.yml@v1": "not pinned",
    }
    for line, expected in bad.items():
        errors = check_uses("bad.yml", line)
        assert len(errors) == 1 and expected in errors[0], (line, errors)
    print("workflow_policy self-test passed")


def main(argv):
    args = argv[1:]
    if args[:1] == ["--self-test"]:
        self_test()
        args = args[1:]
    root = args[0] if args else os.getcwd()
    errors = check(root)
    for error in errors:
        print(f"::error::{error}")
    if errors:
        print(f"workflow policy: {len(errors)} problem(s)", file=sys.stderr)
        return 1
    print("workflow policy: every action is pinned to a full commit SHA")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
