"""Extract manifest keys and dependency names only; never retain config values."""

import json
import re
import tomllib

import yaml

from sentinel.models.base import stable_id
from sentinel.models.evidence import Evidence
from sentinel.models.graph import Node

from .python_ast import FileFacts


def extract_config(repository_id, path, text, file_hash, commit):
    facts = FileFacts(path=path)
    keys, dependencies = [], []
    try:
        if path.endswith(".toml"):
            data = tomllib.loads(text)
            dependencies = data.get("project", {}).get("dependencies", [])
        elif path.endswith(".json"):
            data = json.loads(text)
        elif path.endswith((".yaml", ".yml")):
            if any(isinstance(t, (yaml.tokens.AliasToken, yaml.tokens.AnchorToken)) for t in yaml.scan(text)):
                raise ValueError("YAML aliases are outside the bounded parser")
            data = yaml.safe_load(text)
        elif path.endswith("requirements.txt"):
            data = {}
            dependencies = text.splitlines()
        else:
            data = {
                line.split("=", 1)[0].strip(): None
                for line in text.splitlines()
                if "=" in line and not line.lstrip().startswith("#")
            }
        if isinstance(data, dict):
            keys = sorted(
                k for k in data if isinstance(k, str) and re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", k)
            )[:100]
    except (ValueError, yaml.YAMLError, RecursionError):
        facts.warnings.append(f"Unable to parse config safely: {path}")
    eid = stable_id("evidence", repository_id, path, file_hash, "manifest")
    facts.evidence.append(
        Evidence(
            id=eid,
            path=path,
            start_line=1,
            end_line=max(1, len(text.splitlines())),
            commit=commit,
            claim="Manifest keys extracted; values omitted",
        )
    )
    facts.nodes.append(
        Node(
            id=stable_id("config", repository_id, path),
            type="CONFIG",
            name=path,
            path=path,
            evidence_ids=[eid],
            attributes={"keys": keys},
        )
    )
    if not isinstance(dependencies, list):
        dependencies = []
        facts.warnings.append(f"Invalid manifest dependency list: {path}")
    for dep in dependencies[:100]:
        if not isinstance(dep, str):
            continue
        match = re.match(r"^([A-Za-z0-9][A-Za-z0-9_.-]*)", dep)
        if match:
            name = match.group(1)
            facts.nodes.append(
                Node(
                    id=stable_id("dependency", repository_id, path, name),
                    type="DEPENDENCY",
                    name=name,
                    path=path,
                    evidence_ids=[eid],
                    attributes={"trust": "unknown"},
                )
            )
    return facts
