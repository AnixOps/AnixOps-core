"""Add opt-in output to fixture tests in a disposable Actions checkout."""

import json
import os
from pathlib import Path
import re
import sys


def instrument(source, test, output_names):
    start = source.index(f"    fn {test}() {{")
    end = source.index("\n    }", start)
    body = source[start:end]
    pattern = re.compile(r"^        let value = snapshot\(.*\);$", re.MULTILINE)
    if len(pattern.findall(body)) != len(output_names):
        raise ValueError(f"Unexpected snapshot count in {test}")
    names = iter(output_names)

    def add_output(match):
        name = next(names)
        if name is None:
            return match[0]
        return match[0] + (
            "\n        if let Some(dir) = std::env::var_os(\"R28_SNAPSHOT_OUTPUT\") {"
            f'\n            let path = std::path::PathBuf::from(dir).join("{name}.json");'
            "\n            std::fs::write(path, serde_json::to_vec(&value).unwrap()).unwrap();"
            "\n        }"
        )

    return source[:start] + pattern.sub(add_output, body) + source[end:]


def main():
    snapshot = Path(sys.argv[1]) / "crates/outbound-mesh/src/outbound/snapshot.rs"
    source = instrument(
        snapshot.read_text(encoding="utf-8"),
        "a_joined_network_lists_members_paths_and_subnets",
        ["joined"],
    )
    label = os.environ["CORE_LABEL"]
    if label != "core-0.3.0":
        source = instrument(
            source,
            "names_are_listed_with_their_duplicates_in_other_networks",
            ["office-all-running", "paris-all-running", None, "office-lab-stopped", None, None],
        )
    snapshot.write_text(source, encoding="utf-8")

    output = Path(os.environ["R28_SNAPSHOT_OUTPUT"])
    output.mkdir(parents=True)
    provenance = {
        "coreSha": os.environ["CORE_SHA"],
        "coreLabel": label,
        "harnessSha": os.environ["GITHUB_SHA"],
        "run": f'{os.environ["GITHUB_SERVER_URL"]}/{os.environ["GITHUB_REPOSITORY"]}'
        f'/actions/runs/{os.environ["GITHUB_RUN_ID"]}',
        "command": "cargo test --locked -p outbound-mesh --features outbound "
        "--lib outbound::snapshot::tests",
        "input": "Existing synthetic Rust fixtures, no deployment configuration or live peers",
        "output": "Unmodified production snapshot() value written with serde_json::to_vec",
    }
    (output / "provenance.json").write_text(
        json.dumps(provenance, indent=2) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    main()
