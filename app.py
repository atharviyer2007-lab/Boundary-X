from __future__ import annotations

import copy
import itertools
import json
import os
import re
import secrets
import sqlite3
import sys
import tempfile
import time
import unittest
from dataclasses import dataclass, field
from datetime import datetime, timezone
from functools import wraps
from typing import Callable, Optional

from flask import Flask, jsonify, request, send_from_directory


@dataclass
class Node:
    id: str
    label: str
    kind: str = "service"
    critical: bool = False
    sensitive: bool = False
    workflows: int = 0
    untrusted: bool = False


@dataclass
class Edge:
    src: str
    dst: str
    condition: Optional[str] = None


@dataclass
class Graph:
    nodes: dict = field(default_factory=dict)
    edges: list = field(default_factory=list)

    def add_node(self, node: Node):
        self.nodes[node.id] = node

    def add_edge(self, edge: Edge):
        self.edges.append(edge)

    def clone(self) -> "Graph":
        return copy.deepcopy(self)


def matches(identity_pattern: str, condition: Optional[str]) -> bool:
    if condition is None:
        return True
    if condition == "*":
        return True
    return identity_pattern == condition


def reachable_sensitive_from_untrusted(graph: Graph) -> tuple[bool, list[str]]:
    adjacency: dict[str, list[Edge]] = {}
    for e in graph.edges:
        adjacency.setdefault(e.src, []).append(e)

    for start_id, start in graph.nodes.items():
        if not start.untrusted:
            continue
        visited = {start_id}
        queue = [(start_id, [start_id])]
        while queue:
            cur, path = queue.pop(0)
            for e in adjacency.get(cur, []):
                if not matches(start.label, e.condition):
                    continue
                if e.dst in visited:
                    continue
                visited.add(e.dst)
                new_path = path + [e.dst]
                if graph.nodes[e.dst].sensitive:
                    return True, new_path
                queue.append((e.dst, new_path))
    return False, []


def reachable_set_from_untrusted(graph: Graph) -> set[str]:
    adjacency: dict[str, list[Edge]] = {}
    for e in graph.edges:
        adjacency.setdefault(e.src, []).append(e)

    visited: set[str] = set()
    for start_id, start in graph.nodes.items():
        if not start.untrusted:
            continue
        visited.add(start_id)
        queue = [start_id]
        while queue:
            cur = queue.pop(0)
            for e in adjacency.get(cur, []):
                if not matches(start.label, e.condition):
                    continue
                if e.dst in visited:
                    continue
                visited.add(e.dst)
                queue.append(e.dst)
    return visited


def downstream_of(graph: Graph, start_id: str) -> set[str]:
    adjacency: dict[str, list[str]] = {}
    for e in graph.edges:
        adjacency.setdefault(e.src, []).append(e.dst)
    visited = set()
    queue = [start_id]
    while queue:
        cur = queue.pop(0)
        for nxt in adjacency.get(cur, []):
            if nxt not in visited:
                visited.add(nxt)
                queue.append(nxt)
    return visited


def build_baseline_graph() -> Graph:
    g = Graph()
    g.add_node(Node("external_identity", "any-github-repo", kind="identity", untrusted=True))
    g.add_node(Node("trusted_org_identity", "trusted-org/*", kind="identity"))
    g.add_node(Node("oidc_trust", "github-oidc-trust", kind="iam"))
    g.add_node(Node("prod_deploy_role", "prod-deploy-role", kind="iam"))
    g.add_node(Node("github_actions_runner", "GitHub Actions", kind="service", workflows=1))
    g.add_node(Node("artifact_registry", "artifact-registry", kind="service", workflows=1))
    g.add_node(Node("payments_api", "payments-api", kind="service", critical=True, workflows=1))
    g.add_node(Node("secrets_manager", "secrets-manager", kind="data", critical=True))
    g.add_node(Node("customer_data", "customer-data (RDS)", kind="data", sensitive=True))

    g.add_edge(Edge("trusted_org_identity", "oidc_trust", condition="trusted-org/*"))
    g.add_edge(Edge("external_identity", "oidc_trust", condition="trusted-org/*"))
    g.add_edge(Edge("oidc_trust", "prod_deploy_role"))
    g.add_edge(Edge("prod_deploy_role", "github_actions_runner"))
    g.add_edge(Edge("github_actions_runner", "artifact_registry"))
    g.add_edge(Edge("artifact_registry", "payments_api"))
    g.add_edge(Edge("payments_api", "secrets_manager"))
    g.add_edge(Edge("secrets_manager", "customer_data"))
    return g


def widen_oidc_trust(g: Graph) -> None:
    for e in g.edges:
        if e.src == "external_identity" and e.dst == "oidc_trust":
            e.condition = "*"


def _slugify(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_") or "resource"


def make_generic_widening_effect(resource_id: str, resource_label: str, kind: str) -> Callable[[Graph], None]:
    """Build a graph effect for a security-relevant widening that isn't one
    of the demo's known hardcoded edges (e.g. an IAM condition or network
    CIDR loosened to "*"/0.0.0.0/0 in a resource outside the illustrative
    OIDC scenario).

    Rather than only flagging these and doing nothing to the graph (which
    would make the "minimum causal change" engine blind to anything but the
    one baked-in edge), this models the affected resource as a new node
    reachable from an untrusted identity, wired to whatever sensitive data
    exists downstream — so the same reachability search, blast-radius BFS,
    and counterfactual minimum-change logic apply to it like any other
    finding. It's still a simplification (real topology would come from
    actual Terraform/K8s/IAM plan output, not just the diff text), but it
    means the engine's core claim — causal attribution, not just detection
    — actually holds for diffs outside the demo scenario.
    """

    def effect(g: Graph) -> None:
        if resource_id in g.nodes:
            for e in g.edges:
                if e.dst == resource_id and e.src == "external_identity":
                    e.condition = "*"
                    return
        g.add_node(Node(resource_id, resource_label, kind=kind))
        g.add_edge(Edge("external_identity", resource_id, condition="*"))
        for n in list(g.nodes.values()):
            if n.sensitive and n.id != resource_id:
                g.add_edge(Edge(resource_id, n.id))

    return effect


@dataclass
class Change:
    id: int
    domain: str
    description: str
    effect: Optional[Callable[[Graph], None]] = None
    diff: Optional[dict] = None
    security_pattern_detected: bool = False
    remediation_action: Optional[str] = None


CHANGES: list[Change] = [
    Change(1, "terraform", "vpc-prod: subnet CIDR expanded"),
    Change(2, "k8s", "payments-api: replica count 3→5"),
    Change(3, "cicd", "workflow: cache step added"),
    Change(4, "iam", "logging-role: added cloudwatch:PutLogEvents"),
    Change(5, "networking", "sg-internal: port 9090 opened (private)"),
    Change(6, "terraform", "rds-customer-data: storage 100→200GB"),
    Change(
        7,
        "iam",
        'github-oidc-trust: repository "trusted-org/*" → "*"',
        effect=widen_oidc_trust,
        diff={
            "file": "iam.tf",
            "line": "@@ -6,7 +6,7 @@",
            "remove": 'StringLike: "token.actions.githubusercontent.com:sub" = "repo:trusted-org/*"',
            "add": 'StringLike: "token.actions.githubusercontent.com:sub" = "repo:*"',
        },
        security_pattern_detected=True,
        remediation_action="Restore repository condition on the OIDC trust policy",
    ),
    Change(8, "k8s", "payments-api: readiness probe timeout +5s"),
    Change(9, "cicd", "deploy.yml: matrix build for arm64 added"),
    Change(10, "terraform", "s3-static-assets: versioning enabled"),
    Change(11, "networking", "alb-prod: idle timeout 60→120s"),
    Change(12, "iam", "prod-deploy-role: session duration 1h→2h"),
    Change(13, "k8s", "internal-vpc: network policy label updated"),
    Change(14, "terraform", "cloudtrail: retention 90→365 days"),
    Change(15, "cicd", "lint.yml: eslint version bump"),
    Change(16, "networking", "route-table-prod: comment updated"),
    Change(17, "iam", "backup-role: added s3:GetObject on backups bucket"),
]


def apply_changes(base: Graph, changes: list[Change]) -> Graph:
    g = base.clone()
    for c in changes:
        if c.effect:
            c.effect(g)
    return g


FILE_HEADER_RE = re.compile(r"^diff --git a/(?P<a>\S+) b/(?P<b>\S+)")
OLD_FILE_RE = re.compile(r"^--- (?:a/)?(?P<path>\S+)")
NEW_FILE_RE = re.compile(r"^\+\+\+ (?:b/)?(?P<path>\S+)")
HUNK_HEADER_RE = re.compile(r"^(@@ -\d+(?:,\d+)? \+\d+(?:,\d+)? @@)(.*)$")
ASSIGNED_VALUE_RE = re.compile(r'=\s*"(?P<value>[^"]*)"\s*,?\s*$')

DOMAIN_RULES: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\.github/workflows/|workflow|pipeline|\.gitlab-ci", re.I), "cicd"),
    (re.compile(r"iam|[-_]role|policy|openid|trust|assume", re.I), "iam"),
    (re.compile(r"\bsg[-_.]|security[-_]?group|\bvpc\b|network|route[-_]?table|\balb\b|firewall|\bnsg\b|ingress|egress", re.I), "networking"),
    (re.compile(r"deployment|k8s|kubernetes|helm|\.ya?ml$", re.I), "k8s"),
    (re.compile(r"\.tf$", re.I), "terraform"),
]


@dataclass
class DiffHunk:
    file_path: str
    header: str = ""
    removed: list[str] = field(default_factory=list)
    added: list[str] = field(default_factory=list)


def parse_unified_diff(diff_text: str) -> list[DiffHunk]:
    hunks: list[DiffHunk] = []
    current_path = "unknown"
    current: Optional[DiffHunk] = None

    for raw_line in diff_text.splitlines():
        line = raw_line.rstrip("\n")

        m = FILE_HEADER_RE.match(line)
        if m:
            current_path = m.group("b") or m.group("a")
            current = None
            continue

        m = NEW_FILE_RE.match(line)
        if m:
            if m.group("path") != "/dev/null":
                current_path = m.group("path")
            current = None
            continue

        if OLD_FILE_RE.match(line):
            continue

        m = HUNK_HEADER_RE.match(line)
        if m:
            current = DiffHunk(file_path=current_path, header=m.group(1))
            hunks.append(current)
            continue

        if current is None:
            continue

        if line.startswith("+") and not line.startswith("+++"):
            current.added.append(line[1:].strip())
        elif line.startswith("-") and not line.startswith("---"):
            current.removed.append(line[1:].strip())

    return hunks


def classify_domain(file_path: str) -> str:
    for pattern, domain in DOMAIN_RULES:
        if pattern.search(file_path):
            return domain
    return "other"


def _extract_assigned_value(line: str) -> Optional[str]:
    m = ASSIGNED_VALUE_RE.search(line)
    return m.group("value") if m else None


ASSIGNED_LIST_VALUE_RE = re.compile(r'=\s*\[\s*"(?P<value>[^"]*)"\s*\]\s*,?\s*$')


def _extract_assigned_list_value(line: str) -> Optional[str]:
    """Handle single-element list assignments like cidr_blocks = ["0.0.0.0/0"],
    which is the common Terraform shape for security-group/ingress rules and
    won't match the plain-string ASSIGNED_VALUE_RE above."""
    m = ASSIGNED_LIST_VALUE_RE.search(line)
    return m.group("value") if m else None


def _extract_iam_or_network_value(line: str) -> Optional[str]:
    val = _extract_assigned_value(line)
    return val if val is not None else _extract_assigned_list_value(line)


def _condition_widened(old_val: str, new_val: str) -> bool:
    if old_val == new_val:
        return False
    if new_val == "*" and old_val != "*":
        return True
    if ":" in old_val and ":" in new_val:
        old_prefix, old_suffix = old_val.split(":", 1)
        new_prefix, new_suffix = new_val.split(":", 1)
        if old_prefix == new_prefix and new_suffix == "*" and old_suffix != "*":
            return True
    return False


BROAD_CIDRS = {"0.0.0.0/0", "::/0", "*"}


def _network_exposure_widened(old_val: str, new_val: str) -> bool:
    if old_val == new_val:
        return False
    return new_val in BROAD_CIDRS and old_val not in BROAD_CIDRS


def _matches_known_oidc_edge(hunk: DiffHunk, old_line: str, new_line: str) -> bool:
    haystack = " ".join([hunk.file_path, hunk.header, old_line, new_line]).lower()
    return "githubusercontent.com:sub" in haystack or ("trusted-org" in haystack and "repo:" in haystack)


def summarize_hunk(hunk: DiffHunk) -> str:
    def short(s: str) -> str:
        return s if len(s) <= 64 else s[:61] + "..."

    removed = [l for l in hunk.removed if l]
    added = [l for l in hunk.added if l]
    if len(removed) == 1 and len(added) == 1:
        return f"{hunk.file_path}: {short(removed[0])} → {short(added[0])}"
    if added and not removed:
        return f"{hunk.file_path}: +{len(added)} line(s) ({short(added[0])})"
    if removed and not added:
        return f"{hunk.file_path}: -{len(removed)} line(s) ({short(removed[0])})"
    if added or removed:
        return f"{hunk.file_path}: {len(removed)} removed, {len(added)} added"
    return f"{hunk.file_path}: {hunk.header}".strip()


def _paired_lines(removed: list[str], added: list[str]) -> list[tuple[str, str]]:
    if len(removed) == len(added):
        return list(zip(removed, added))
    return list(itertools.product(removed, added))


def changes_from_diff(diff_text: str, start_id: int = 1) -> tuple[list[Change], list[str], list[str]]:
    hunks = parse_unified_diff(diff_text)
    warnings: list[str] = []
    if not hunks:
        warnings.append("No unified-diff hunks found (expected '@@ ... @@' hunk headers).")
        return [], [], warnings

    changes: list[Change] = []
    files_touched: list[str] = []

    for i, hunk in enumerate(hunks):
        if hunk.file_path not in files_touched:
            files_touched.append(hunk.file_path)

        domain = classify_domain(hunk.file_path)
        description = summarize_hunk(hunk)
        effect = None
        diff_excerpt: Optional[dict] = None
        security_pattern = False

        if domain == "iam":
            for old_line, new_line in _paired_lines(hunk.removed, hunk.added):
                old_val = _extract_assigned_value(old_line)
                new_val = _extract_assigned_value(new_line)
                if old_val is None or new_val is None:
                    continue
                if _condition_widened(old_val, new_val):
                    security_pattern = True
                    diff_excerpt = {
                        "file": hunk.file_path,
                        "line": hunk.header or "(hunk)",
                        "remove": old_line,
                        "add": new_line,
                    }
                    if _matches_known_oidc_edge(hunk, old_line, new_line):
                        effect = widen_oidc_trust
                    else:
                        resource_id = f"iam_{i}_{_slugify(hunk.file_path)}"
                        resource_label = os.path.splitext(os.path.basename(hunk.file_path))[0]
                        effect = make_generic_widening_effect(resource_id, resource_label, kind="iam")
                    break

        elif domain == "networking":
            for old_line, new_line in _paired_lines(hunk.removed, hunk.added):
                old_val = _extract_iam_or_network_value(old_line)
                new_val = _extract_iam_or_network_value(new_line)
                if old_val is None or new_val is None:
                    continue
                if _network_exposure_widened(old_val, new_val):
                    security_pattern = True
                    diff_excerpt = {
                        "file": hunk.file_path,
                        "line": hunk.header or "(hunk)",
                        "remove": old_line,
                        "add": new_line,
                    }
                    resource_id = f"net_{i}_{_slugify(hunk.file_path)}"
                    resource_label = os.path.splitext(os.path.basename(hunk.file_path))[0]
                    effect = make_generic_widening_effect(resource_id, resource_label, kind="network")
                    break

        changes.append(
            Change(
                id=start_id + i,
                domain=domain,
                description=description,
                effect=effect,
                diff=diff_excerpt,
                security_pattern_detected=security_pattern,
            )
        )

    return changes, files_touched, warnings


def build_live_snapshot(changes: Optional[list[Change]] = None) -> dict:
    changes = CHANGES if changes is None else changes
    baseline = build_baseline_graph()
    live = apply_changes(baseline, changes)

    crossed, path = reachable_sensitive_from_untrusted(live)
    reachable = reachable_set_from_untrusted(live)

    baseline_by_key = {(e.src, e.dst): e for e in baseline.edges}
    live_by_key = {(e.src, e.dst): e for e in live.edges}
    drift = []
    for key in sorted(set(baseline_by_key) | set(live_by_key)):
        before = baseline_by_key.get(key)
        after = live_by_key.get(key)
        before_condition = before.condition if before else None
        after_condition = after.condition if after else None
        if before_condition == after_condition:
            continue
        src, dst = key
        drift.append(
            {
                "src": src,
                "dst": dst,
                "src_label": live.nodes[src].label if src in live.nodes else baseline.nodes[src].label,
                "dst_label": live.nodes[dst].label if dst in live.nodes else baseline.nodes[dst].label,
                "before_condition": before_condition,
                "after_condition": after_condition,
            }
        )

    return {
        "source": "live",
        "fetched_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "graph": graph_export(live),
        "reachable_from_untrusted": sorted(reachable),
        "boundary_crossed": crossed,
        "attack_path": {
            "ids": path,
            "labels": [live.nodes[n].label for n in path] if path else [],
        },
        "drift": {
            "edges_changed": drift,
            "summary": (
                f"{len(drift)} trust condition(s) drifted from the known-good baseline"
                if drift
                else "No drift from the known-good baseline"
            ),
        },
    }


def find_minimum_causal_changes(base: Graph, all_changes: list[Change], max_subset_size: int = 3):
    causal, _truncated = _minimum_causal_change_search(
        base, all_changes, max_subset_size,
        time_budget_seconds=None, max_combinations=None,
    )
    return causal


DEFAULT_SEARCH_TIME_BUDGET_SECONDS = 2.0
DEFAULT_SEARCH_MAX_COMBINATIONS = 20_000


def find_minimum_causal_changes_bounded(
    base: Graph,
    all_changes: list[Change],
    max_subset_size: int = 3,
    time_budget_seconds: float = DEFAULT_SEARCH_TIME_BUDGET_SECONDS,
    max_combinations: int = DEFAULT_SEARCH_MAX_COMBINATIONS,
) -> tuple[list[Change], bool]:
    """Same leave-N-out counterfactual search as find_minimum_causal_changes,
    but gives up and reports truncated=True once it exceeds a time or
    combination budget, instead of running unbounded O(n^k) search on
    arbitrary user-supplied input (e.g. a large pasted diff). This is what
    run_analysis() uses for anything reachable from the API; the plain
    unbounded version above stays available for small/trusted change sets
    (the demo scenario, unit tests) where an exhaustive answer is cheap and
    truncation would never trigger anyway."""
    return _minimum_causal_change_search(
        base, all_changes, max_subset_size, time_budget_seconds, max_combinations
    )


def _minimum_causal_change_search(
    base: Graph,
    all_changes: list[Change],
    max_subset_size: int,
    time_budget_seconds: Optional[float],
    max_combinations: Optional[int],
) -> tuple[list[Change], bool]:
    full_after = apply_changes(base, all_changes)
    crossed, _ = reachable_sensitive_from_untrusted(full_after)
    if not crossed:
        return [], False

    start = time.monotonic()
    combos_tried = 0

    for subset_size in range(1, max_subset_size + 1):
        for subset in itertools.combinations(all_changes, subset_size):
            combos_tried += 1
            if max_combinations is not None and combos_tried > max_combinations:
                return [], True
            if time_budget_seconds is not None and (time.monotonic() - start) > time_budget_seconds:
                return [], True
            remaining = [c for c in all_changes if c not in subset]
            g = apply_changes(base, remaining)
            still_crossed, _ = reachable_sensitive_from_untrusted(g)
            if not still_crossed:
                return list(subset), False
    return [], False


def graph_export(graph: Graph) -> dict:
    return {
        "nodes": [
            {
                "id": n.id,
                "label": n.label,
                "kind": n.kind,
                "critical": n.critical,
                "sensitive": n.sensitive,
                "workflows": n.workflows,
                "untrusted": n.untrusted,
            }
            for n in graph.nodes.values()
        ],
        "edges": [{"src": e.src, "dst": e.dst, "condition": e.condition} for e in graph.edges],
    }


def run_analysis(
    changes: Optional[list[Change]] = None,
    time_budget_seconds: float = DEFAULT_SEARCH_TIME_BUDGET_SECONDS,
    max_combinations: int = DEFAULT_SEARCH_MAX_COMBINATIONS,
) -> dict:
    changes = CHANGES if changes is None else changes
    baseline = build_baseline_graph()

    before_crossed, _ = reachable_sensitive_from_untrusted(baseline)
    before_reachable = reachable_set_from_untrusted(baseline)

    after = apply_changes(baseline, changes)
    after_crossed, path = reachable_sensitive_from_untrusted(after)
    after_reachable = reachable_set_from_untrusted(after)

    causal, search_truncated = find_minimum_causal_changes_bounded(
        baseline, changes, time_budget_seconds=time_budget_seconds, max_combinations=max_combinations
    )

    blast = {"resources": 0, "critical_services": 0, "sensitive_datastores": 0, "user_workflows": 0}
    if after_crossed and path:
        start = path[1] if len(path) > 1 else path[0]
        downstream = downstream_of(after, start)
        blast["resources"] = len(downstream)
        blast["critical_services"] = sum(1 for n in downstream if after.nodes[n].critical)
        blast["sensitive_datastores"] = sum(1 for n in downstream if after.nodes[n].sensitive)
        blast["user_workflows"] = sum(after.nodes[n].workflows for n in downstream)

    security_relevant = [c for c in changes if c.domain in ("iam", "networking")]

    remediation = None
    if causal:
        top = causal[0]
        action = top.remediation_action or f"Revert change #{top.id} ({top.description})"
        if top.diff:
            remediation = {
                "change_id": top.id,
                "action": action,
                "diff": {
                    "file": top.diff["file"],
                    "line": top.diff["line"],
                    "remove": top.diff["add"],
                    "add": top.diff["remove"],
                },
            }
        else:
            remediation = {"change_id": top.id, "action": action, "diff": None}

    return {
        "changes_submitted": len(changes),
        "security_relevant_changes": len(security_relevant),
        "before_state_safe": not before_crossed,
        "after_state_safe": not after_crossed,
        "boundary_crossed": after_crossed,
        "attack_path": {
            "ids": path,
            "labels": [after.nodes[n].label for n in path] if path else [],
        },
        "graph": graph_export(baseline),
        "graph_before": graph_export(baseline),
        "graph_after": graph_export(after),
        "before_reachable": sorted(before_reachable),
        "after_reachable": sorted(after_reachable),
        "minimum_causal_changes": [
            {"id": c.id, "domain": c.domain, "description": c.description} for c in causal
        ],
        "search_truncated": search_truncated,
        "blast_radius": blast,
        "remediation": remediation,
    }


# --- Persistence ---------------------------------------------------------
# Every completed analysis (sample-PR or diff-ingestion) is written to a
# small SQLite file so the dashboard's "Recent analyses" list and report
# downloads survive a server restart. Overridable via BOUNDARY_X_DB_PATH
# (used by the test suite to isolate its own throwaway database).
DB_PATH = os.environ.get("BOUNDARY_X_DB_PATH", "boundaryx.db")


def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    conn = get_db()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS analyses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            source TEXT NOT NULL,
            pr_tag TEXT,
            repo TEXT,
            changes_submitted INTEGER,
            boundary_crossed INTEGER,
            causal_change_id INTEGER,
            causal_description TEXT,
            blast_resources INTEGER,
            blast_critical INTEGER,
            blast_datastores INTEGER,
            blast_workflows INTEGER,
            status TEXT,
            result_json TEXT NOT NULL
        )
        """
    )
    conn.commit()
    conn.close()


def _status_for(result: dict) -> str:
    if not result["boundary_crossed"]:
        return "safe"
    blast = result.get("blast_radius") or {}
    if blast.get("sensitive_datastores", 0) > 0 or blast.get("critical_services", 0) >= 2:
        return "critical"
    return "high"


def record_analysis(result: dict, source: str, pr_tag: str = "", repo: str = "") -> int:
    causal = result["minimum_causal_changes"][0] if result.get("minimum_causal_changes") else None
    blast = result.get("blast_radius") or {}
    conn = get_db()
    cur = conn.execute(
        """INSERT INTO analyses (
            created_at, source, pr_tag, repo, changes_submitted, boundary_crossed,
            causal_change_id, causal_description, blast_resources, blast_critical,
            blast_datastores, blast_workflows, status, result_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
            source,
            pr_tag,
            repo,
            result["changes_submitted"],
            1 if result["boundary_crossed"] else 0,
            causal["id"] if causal else None,
            causal["description"] if causal else None,
            blast.get("resources", 0),
            blast.get("critical_services", 0),
            blast.get("sensitive_datastores", 0),
            blast.get("user_workflows", 0),
            _status_for(result),
            json.dumps(result),
        ),
    )
    conn.commit()
    analysis_id = cur.lastrowid
    conn.close()
    return analysis_id


def get_recent_analyses(limit: int = 10) -> list[dict]:
    conn = get_db()
    rows = conn.execute(
        """SELECT id, created_at, source, pr_tag, repo, changes_submitted,
                  boundary_crossed, causal_change_id, causal_description,
                  blast_resources, blast_critical, blast_datastores, blast_workflows, status
           FROM analyses ORDER BY id DESC LIMIT ?""",
        (limit,),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_stored_analysis(analysis_id: int) -> Optional[dict]:
    conn = get_db()
    row = conn.execute(
        "SELECT result_json FROM analyses WHERE id = ?", (analysis_id,)
    ).fetchone()
    conn.close()
    if row is None:
        return None
    return json.loads(row["result_json"])


app = Flask(__name__, static_folder=None)
init_db()

STATIC_EXTENSIONS = {
    ".html", ".css", ".js", ".json", ".svg", ".png", ".jpg", ".jpeg",
    ".gif", ".ico", ".webp", ".woff", ".woff2", ".ttf", ".map", ".txt",
}

# --- API auth -----------------------------------------------------------
# A per-process API key is required on every /api/* route except /api/health.
# It's read from BOUNDARY_X_API_KEY if set (e.g. for a shared/deployed
# instance), otherwise a random key is generated fresh on each startup and
# printed to the console, and automatically injected into the page served
# at "/" so the frontend picks it up without any manual setup on localhost.
API_KEY = os.environ.get("BOUNDARY_X_API_KEY") or secrets.token_hex(24)


def require_api_key(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        supplied = request.headers.get("X-API-Key", "")
        if not secrets.compare_digest(supplied, API_KEY):
            return jsonify({"error": "Missing or invalid API key."}), 401
        return fn(*args, **kwargs)
    return wrapper


@app.get("/api/changes")
@require_api_key
def api_changes():
    return jsonify([{"id": c.id, "domain": c.domain, "description": c.description} for c in CHANGES])


@app.post("/api/analyze")
@require_api_key
def api_analyze():
    result = run_analysis()
    result["analysis_id"] = record_analysis(
        result, source="sample", pr_tag="PR #1843", repo="payments-api"
    )
    return jsonify(result)


@app.post("/api/ingest-diff")
@require_api_key
def api_ingest_diff():
    payload = request.get_json(silent=True) or {}
    diff_text = payload.get("diff", "")
    if not isinstance(diff_text, str) or not diff_text.strip():
        return jsonify({"error": "Request body must include a non-empty 'diff' string."}), 400

    changes, files_touched, warnings = changes_from_diff(diff_text)
    if not changes:
        return jsonify({"error": "Could not parse any hunks from the supplied diff.", "warnings": warnings}), 422

    result = run_analysis(changes)
    result["source"] = "diff_ingestion"
    result["files_touched"] = files_touched
    result["parse_warnings"] = warnings
    result["parsed_changes"] = [
        {
            "id": c.id,
            "domain": c.domain,
            "description": c.description,
            "security_pattern_detected": c.security_pattern_detected,
        }
        for c in changes
    ]
    pr_tag = f"Pasted diff · {len(files_touched)} file(s)"
    result["analysis_id"] = record_analysis(
        result,
        source="diff_ingestion",
        pr_tag=pr_tag,
        repo=(files_touched[0] if files_touched else ""),
    )
    return jsonify(result)


@app.get("/api/snapshot")
@require_api_key
def api_snapshot():
    return jsonify(build_live_snapshot())


@app.get("/api/recent")
@require_api_key
def api_recent():
    limit = request.args.get("limit", default=10, type=int)
    return jsonify(get_recent_analyses(limit=limit))


@app.get("/api/report/<int:analysis_id>")
@require_api_key
def api_report(analysis_id):
    result = get_stored_analysis(analysis_id)
    if result is None:
        return jsonify({"error": "No analysis found with that id."}), 404
    return jsonify(result)


@app.get("/api/health")
def health():
    # Intentionally unauthenticated — lets a health check confirm the server
    # is up without needing the key first.
    return jsonify({"status": "ok"})


@app.get("/")
def serve_index():
    # Inject the current process's API key into the page so the frontend can
    # send it automatically. Only "/" is templated this way; static assets
    # below are served as plain files.
    with open("index.html", "r", encoding="utf-8") as f:
        html = f.read()
    html = html.replace("%%API_KEY%%", API_KEY)
    return html, 200, {"Content-Type": "text/html; charset=utf-8"}


@app.get("/<path:filename>")
def serve_static(filename):
    if os.path.splitext(filename)[1].lower() not in STATIC_EXTENSIONS:
        return "Not Found", 404
    return send_from_directory(".", filename)

OIDC_WIDENING_DIFF = """diff --git a/iam.tf b/iam.tf
index 1111111..2222222 100644
--- a/iam.tf
+++ b/iam.tf
@@ -6,7 +6,7 @@ resource "aws_iam_openid_connect_provider" "github" {
       Condition = {
         StringLike = {
-          "token.actions.githubusercontent.com:sub" = "repo:trusted-org/*"
+          "token.actions.githubusercontent.com:sub" = "repo:*"
         }
       }
"""

BENIGN_MULTI_FILE_DIFF = """diff --git a/deploy.tf b/deploy.tf
index 3333333..4444444 100644
--- a/deploy.tf
+++ b/deploy.tf
@@ -12,3 +12,3 @@ resource "aws_db_instance" "customer_data" {
-  allocated_storage = 100
+  allocated_storage = 200
diff --git a/k8s/deploy.yaml b/k8s/deploy.yaml
index 5555555..6666666 100644
--- a/k8s/deploy.yaml
+++ b/k8s/deploy.yaml
@@ -3,3 +3,3 @@
-  replicas: 3
+  replicas: 5
"""

PLAIN_UNIFIED_DIFF = """--- a/security-groups.tf
+++ b/security-groups.tf
@@ -4,2 +4,2 @@
-  from_port = 22
+  from_port = 9090
"""

UNEVEN_OIDC_DIFF = """diff --git a/iam.tf b/iam.tf
--- a/iam.tf
+++ b/iam.tf
@@ -6,12 +6,15 @@
-          "token.actions.githubusercontent.com:sub" = "repo:trusted-org/*"
+          "token.actions.githubusercontent.com:sub" = "repo:*"
+          "aud" = "sts.amazonaws.com"
+          "sub" = "repo:foo/*"
+          "sub" = "repo:bar/*"
+          "sub" = "repo:baz/*"
"""

GENERIC_IAM_WIDENING_DIFF = """diff --git a/s3-bucket-policy.tf b/s3-bucket-policy.tf
--- a/s3-bucket-policy.tf
+++ b/s3-bucket-policy.tf
@@ -10,7 +10,7 @@
-          "aws:PrincipalArn" = "arn:aws:iam::111122223333:role/trusted-role"
+          "aws:PrincipalArn" = "*"
"""

GENERIC_NETWORK_WIDENING_DIFF = """diff --git a/security-groups.tf b/security-groups.tf
--- a/security-groups.tf
+++ b/security-groups.tf
@@ -5,7 +5,7 @@
-  cidr_blocks = ["10.0.0.0/16"]
+  cidr_blocks = ["0.0.0.0/0"]
"""


class TestGraphPrimitives(unittest.TestCase):
    def test_add_node_and_edge(self):
        g = Graph()
        g.add_node(Node("a", "A"))
        g.add_node(Node("b", "B"))
        g.add_edge(Edge("a", "b"))
        self.assertIn("a", g.nodes)
        self.assertEqual(len(g.edges), 1)

    def test_clone_is_a_deep_copy(self):
        g = Graph()
        g.add_node(Node("a", "A"))
        g.add_edge(Edge("a", "a", condition="x"))

        clone = g.clone()
        clone.nodes["a"].label = "changed"
        clone.edges[0].condition = "y"

        self.assertEqual(g.nodes["a"].label, "A")
        self.assertEqual(g.edges[0].condition, "x")

    def test_matches(self):
        self.assertTrue(matches("anything", None))
        self.assertTrue(matches("anything", "*"))
        self.assertTrue(matches("trusted-org/*", "trusted-org/*"))
        self.assertFalse(matches("external/repo", "trusted-org/*"))


class TestReachability(unittest.TestCase):
    def _diamond_graph(self, sensitive_reachable: bool) -> Graph:
        g = Graph()
        g.add_node(Node("attacker", "attacker", kind="identity", untrusted=True))
        g.add_node(Node("gateway", "gateway"))
        g.add_node(Node("internal", "internal"))
        g.add_node(Node("vault", "vault", sensitive=sensitive_reachable))
        g.add_edge(Edge("attacker", "gateway"))
        g.add_edge(Edge("gateway", "internal"))
        if sensitive_reachable:
            g.add_edge(Edge("internal", "vault"))
        return g

    def test_no_path_to_sensitive_is_safe(self):
        g = self._diamond_graph(sensitive_reachable=False)
        crossed, path = reachable_sensitive_from_untrusted(g)
        self.assertFalse(crossed)
        self.assertEqual(path, [])

    def test_path_to_sensitive_is_detected(self):
        g = self._diamond_graph(sensitive_reachable=True)
        crossed, path = reachable_sensitive_from_untrusted(g)
        self.assertTrue(crossed)
        self.assertEqual(path[0], "attacker")
        self.assertEqual(path[-1], "vault")

    def test_condition_blocks_traversal(self):
        g = Graph()
        g.add_node(Node("attacker", "external/repo", kind="identity", untrusted=True))
        g.add_node(Node("trust", "trust"))
        g.add_node(Node("secret", "secret", sensitive=True))
        g.add_edge(Edge("attacker", "trust", condition="trusted-org/*"))
        g.add_edge(Edge("trust", "secret"))

        crossed, _ = reachable_sensitive_from_untrusted(g)
        self.assertFalse(crossed)

    def test_wildcard_condition_allows_traversal(self):
        g = Graph()
        g.add_node(Node("attacker", "external/repo", kind="identity", untrusted=True))
        g.add_node(Node("trust", "trust"))
        g.add_node(Node("secret", "secret", sensitive=True))
        g.add_edge(Edge("attacker", "trust", condition="*"))
        g.add_edge(Edge("trust", "secret"))

        crossed, _ = reachable_sensitive_from_untrusted(g)
        self.assertTrue(crossed)

    def test_reachable_set_includes_start_node(self):
        g = self._diamond_graph(sensitive_reachable=True)
        reachable = reachable_set_from_untrusted(g)
        self.assertEqual(reachable, {"attacker", "gateway", "internal", "vault"})

    def test_downstream_of_excludes_start_node(self):
        g = self._diamond_graph(sensitive_reachable=True)
        downstream = downstream_of(g, "gateway")
        self.assertEqual(downstream, {"internal", "vault"})
        self.assertNotIn("gateway", downstream)

    def test_downstream_of_unknown_node_is_empty(self):
        g = self._diamond_graph(sensitive_reachable=True)
        self.assertEqual(downstream_of(g, "does-not-exist"), set())


class TestBaselineScenario(unittest.TestCase):
    def setUp(self):
        self.baseline = build_baseline_graph()

    def test_baseline_alone_is_safe(self):
        crossed, _ = reachable_sensitive_from_untrusted(self.baseline)
        self.assertFalse(crossed)

    def test_full_change_set_crosses_the_boundary(self):
        after = apply_changes(self.baseline, CHANGES)
        crossed, path = reachable_sensitive_from_untrusted(after)
        self.assertTrue(crossed)
        self.assertEqual(path[0], "external_identity")
        self.assertEqual(path[-1], "customer_data")

    def test_minimum_causal_change_is_change_7(self):
        causal = find_minimum_causal_changes(self.baseline, CHANGES)
        self.assertEqual([c.id for c in causal], [7])

    def test_removing_only_change_7_restores_safety(self):
        remaining = [c for c in CHANGES if c.id != 7]
        after = apply_changes(self.baseline, remaining)
        crossed, _ = reachable_sensitive_from_untrusted(after)
        self.assertFalse(crossed)

    def test_no_changes_is_safe(self):
        causal = find_minimum_causal_changes(self.baseline, [])
        self.assertEqual(causal, [])

    def test_minimum_causal_change_can_be_a_pair(self):
        def _add_exposed_path(g, node_id):
            g.add_node(Node(node_id, node_id))
            g.add_edge(Edge("external_identity", node_id, condition="*"))
            g.add_edge(Edge(node_id, "customer_data"))

        a = Change(1, "iam", "path via a", effect=lambda g, n="exposed_a": _add_exposed_path(g, n))
        b = Change(2, "iam", "path via b", effect=lambda g, n="exposed_b": _add_exposed_path(g, n))

        baseline = build_baseline_graph()
        causal = find_minimum_causal_changes(baseline, [a, b])
        self.assertEqual(sorted(c.id for c in causal), [1, 2])

        self.assertTrue(reachable_sensitive_from_untrusted(apply_changes(baseline, [a]))[0])
        self.assertTrue(reachable_sensitive_from_untrusted(apply_changes(baseline, [b]))[0])


class TestBoundedSearch(unittest.TestCase):
    def setUp(self):
        self.baseline = build_baseline_graph()

    def test_bounded_search_matches_unbounded_when_budget_is_generous(self):
        causal, truncated = find_minimum_causal_changes_bounded(self.baseline, CHANGES)
        self.assertFalse(truncated)
        self.assertEqual([c.id for c in causal], [7])

    def test_bounded_search_reports_truncation_when_combination_budget_is_exceeded(self):
        # Force a combination budget so small it's exceeded on the very
        # first subset tried, on a change set that *does* cross the
        # boundary — this is the case an unbounded search would otherwise
        # keep grinding through on a large real-world diff.
        causal, truncated = find_minimum_causal_changes_bounded(
            self.baseline, CHANGES, max_combinations=0
        )
        self.assertTrue(truncated)
        self.assertEqual(causal, [])

    def test_bounded_search_reports_truncation_when_time_budget_is_exceeded(self):
        causal, truncated = find_minimum_causal_changes_bounded(
            self.baseline, CHANGES, time_budget_seconds=0.0
        )
        self.assertTrue(truncated)
        self.assertEqual(causal, [])

    def test_bounded_search_does_not_truncate_a_safe_change_set(self):
        # No boundary crossing at all — the search should short-circuit
        # before the budget is even relevant.
        causal, truncated = find_minimum_causal_changes_bounded(
            self.baseline, [], max_combinations=0, time_budget_seconds=0.0
        )
        self.assertFalse(truncated)
        self.assertEqual(causal, [])

    def test_unbounded_helper_still_returns_a_plain_list(self):
        # find_minimum_causal_changes() (no budget) stays the simple,
        # backward-compatible entry point used by tests and any direct
        # library caller with a small/trusted change set.
        causal = find_minimum_causal_changes(self.baseline, CHANGES)
        self.assertIsInstance(causal, list)
        self.assertEqual([c.id for c in causal], [7])


class TestRunAnalysis(unittest.TestCase):
    def test_default_analysis_matches_known_scenario(self):
        result = run_analysis()
        self.assertEqual(result["changes_submitted"], 17)
        self.assertEqual(result["security_relevant_changes"], 7)
        self.assertTrue(result["before_state_safe"])
        self.assertFalse(result["after_state_safe"])
        self.assertTrue(result["boundary_crossed"])
        self.assertEqual([c["id"] for c in result["minimum_causal_changes"]], [7])
        self.assertEqual(
            result["blast_radius"],
            {"resources": 6, "critical_services": 2, "sensitive_datastores": 1, "user_workflows": 3},
        )
        self.assertIsNotNone(result["remediation"])
        self.assertEqual(result["remediation"]["change_id"], 7)
        self.assertFalse(result["search_truncated"])

    def test_analysis_reports_search_truncated_when_budget_is_exceeded(self):
        result = run_analysis(CHANGES, max_combinations=0)
        self.assertTrue(result["boundary_crossed"])
        self.assertTrue(result["search_truncated"])
        self.assertEqual(result["minimum_causal_changes"], [])
        self.assertIsNone(result["remediation"])
        # Blast radius is computed from the full after-graph, independent
        # of whether the minimum-change search finished — it should still
        # reflect the real exposure even when the search was cut short.
        self.assertGreater(result["blast_radius"]["resources"], 0)

    def test_analysis_with_empty_change_set_is_safe_and_has_no_remediation(self):
        result = run_analysis([])
        self.assertTrue(result["before_state_safe"])
        self.assertTrue(result["after_state_safe"])
        self.assertFalse(result["boundary_crossed"])
        self.assertEqual(result["minimum_causal_changes"], [])
        self.assertIsNone(result["remediation"])
        self.assertEqual(result["blast_radius"]["resources"], 0)

    def test_analysis_exports_before_and_after_graphs_with_conditions(self):
        result = run_analysis()
        self.assertIn("graph_before", result)
        self.assertIn("graph_after", result)

        oidc_after = next(
            e for e in result["graph_after"]["edges"]
            if e["src"] == "external_identity" and e["dst"] == "oidc_trust"
        )
        self.assertEqual(oidc_after["condition"], "*")

        oidc_before = next(
            e for e in result["graph_before"]["edges"]
            if e["src"] == "external_identity" and e["dst"] == "oidc_trust"
        )
        self.assertEqual(oidc_before["condition"], "trusted-org/*")

        self.assertEqual(result["graph"], result["graph_before"])

    def test_remediation_diff_is_none_when_causal_change_has_no_diff(self):
        c = Change(7, "iam", "widened oidc trust", effect=widen_oidc_trust)
        result = run_analysis([c])
        self.assertTrue(result["boundary_crossed"])
        self.assertEqual(result["remediation"]["change_id"], 7)
        self.assertIsNone(result["remediation"]["diff"])


class TestDiffParsing(unittest.TestCase):
    def test_parses_git_style_hunks(self):
        hunks = parse_unified_diff(OIDC_WIDENING_DIFF)
        self.assertEqual(len(hunks), 1)
        self.assertEqual(hunks[0].file_path, "iam.tf")
        self.assertEqual(hunks[0].removed, ['"token.actions.githubusercontent.com:sub" = "repo:trusted-org/*"'])
        self.assertEqual(hunks[0].added, ['"token.actions.githubusercontent.com:sub" = "repo:*"'])

    def test_parses_plain_unified_diff_without_git_header(self):
        hunks = parse_unified_diff(PLAIN_UNIFIED_DIFF)
        self.assertEqual(len(hunks), 1)
        self.assertEqual(hunks[0].file_path, "security-groups.tf")

    def test_multi_file_diff_produces_one_hunk_per_change(self):
        hunks = parse_unified_diff(BENIGN_MULTI_FILE_DIFF)
        self.assertEqual([h.file_path for h in hunks], ["deploy.tf", "k8s/deploy.yaml"])

    def test_garbage_input_yields_no_hunks(self):
        self.assertEqual(parse_unified_diff("this is not a diff"), [])
        self.assertEqual(parse_unified_diff(""), [])


class TestDomainClassification(unittest.TestCase):
    def test_iam_files(self):
        self.assertEqual(classify_domain("iam.tf"), "iam")
        self.assertEqual(classify_domain("modules/iam/trust-policy.tf"), "iam")

    def test_networking_files(self):
        self.assertEqual(classify_domain("security-groups.tf"), "networking")
        self.assertEqual(classify_domain("sg-internal.tf"), "networking")

    def test_cicd_files(self):
        self.assertEqual(classify_domain(".github/workflows/deploy.yml"), "cicd")

    def test_k8s_files(self):
        self.assertEqual(classify_domain("k8s/deploy.yaml"), "k8s")

    def test_terraform_fallback(self):
        self.assertEqual(classify_domain("s3-static-assets.tf"), "terraform")

    def test_unknown_extension_falls_back_to_other(self):
        self.assertEqual(classify_domain("README.md"), "other")


class TestConditionWidening(unittest.TestCase):
    def test_detects_scoped_suffix_widened_to_wildcard(self):
        self.assertTrue(_condition_widened("repo:trusted-org/*", "repo:*"))

    def test_detects_full_value_widened_to_wildcard(self):
        self.assertTrue(_condition_widened("arn:aws:iam::123:role/deploy", "*"))

    def test_unrelated_value_change_is_not_flagged(self):
        self.assertFalse(_condition_widened("100", "200"))

    def test_identical_values_are_not_flagged(self):
        self.assertFalse(_condition_widened("repo:*", "repo:*"))

    def test_narrowing_is_not_flagged(self):
        self.assertFalse(_condition_widened("repo:*", "repo:trusted-org/*"))


class TestChangesFromDiff(unittest.TestCase):
    def test_oidc_widening_diff_reproduces_the_baseline_finding(self):
        changes, files_touched, warnings = changes_from_diff(OIDC_WIDENING_DIFF)
        self.assertEqual(warnings, [])
        self.assertEqual(files_touched, ["iam.tf"])
        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0].domain, "iam")
        self.assertTrue(changes[0].security_pattern_detected)
        self.assertIs(changes[0].effect, widen_oidc_trust)

        baseline = build_baseline_graph()
        after = apply_changes(baseline, changes)
        crossed, _ = reachable_sensitive_from_untrusted(after)
        self.assertTrue(crossed)

    def test_benign_diff_does_not_cross_the_boundary(self):
        changes, files_touched, warnings = changes_from_diff(BENIGN_MULTI_FILE_DIFF)
        self.assertEqual(warnings, [])
        self.assertEqual(len(changes), 2)
        self.assertTrue(all(not c.security_pattern_detected for c in changes))

        baseline = build_baseline_graph()
        after = apply_changes(baseline, changes)
        crossed, _ = reachable_sensitive_from_untrusted(after)
        self.assertFalse(crossed)

    def test_unparseable_diff_returns_no_changes_and_a_warning(self):
        changes, files_touched, warnings = changes_from_diff("not a real diff")
        self.assertEqual(changes, [])
        self.assertEqual(files_touched, [])
        self.assertEqual(len(warnings), 1)

    def test_ids_are_sequential_from_start_id(self):
        changes, _, _ = changes_from_diff(BENIGN_MULTI_FILE_DIFF, start_id=5)
        self.assertEqual([c.id for c in changes], [5, 6])

    def test_uneven_hunk_still_detects_widening(self):
        changes, _, warnings = changes_from_diff(UNEVEN_OIDC_DIFF)
        self.assertEqual(warnings, [])
        self.assertEqual(len(changes), 1)
        self.assertTrue(changes[0].security_pattern_detected)
        self.assertIs(changes[0].effect, widen_oidc_trust)

    def test_generic_iam_widening_outside_demo_scenario_still_crosses_boundary(self):
        # Not the hardcoded OIDC edge — a different IAM principal widened to
        # "*" in a resource the baseline graph has never heard of. This is
        # exactly the case the generic widening effect exists for.
        changes, files_touched, warnings = changes_from_diff(GENERIC_IAM_WIDENING_DIFF)
        self.assertEqual(warnings, [])
        self.assertEqual(files_touched, ["s3-bucket-policy.tf"])
        self.assertEqual(len(changes), 1)
        self.assertTrue(changes[0].security_pattern_detected)
        self.assertIsNotNone(changes[0].effect)
        self.assertIsNot(changes[0].effect, widen_oidc_trust)

        baseline = build_baseline_graph()
        after = apply_changes(baseline, changes)
        crossed, path = reachable_sensitive_from_untrusted(after)
        self.assertTrue(crossed)
        self.assertEqual(path[0], "external_identity")
        self.assertEqual(path[-1], "customer_data")

    def test_generic_iam_widening_produces_a_remediation_and_blast_radius(self):
        changes, _, _ = changes_from_diff(GENERIC_IAM_WIDENING_DIFF)
        result = run_analysis(changes)
        self.assertTrue(result["boundary_crossed"])
        self.assertEqual(len(result["minimum_causal_changes"]), 1)
        self.assertIsNotNone(result["remediation"])
        self.assertGreater(result["blast_radius"]["sensitive_datastores"], 0)

    def test_generic_network_widening_to_open_cidr_crosses_boundary(self):
        changes, files_touched, warnings = changes_from_diff(GENERIC_NETWORK_WIDENING_DIFF)
        self.assertEqual(warnings, [])
        self.assertEqual(files_touched, ["security-groups.tf"])
        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0].domain, "networking")
        self.assertTrue(changes[0].security_pattern_detected)
        self.assertIsNotNone(changes[0].effect)

        baseline = build_baseline_graph()
        after = apply_changes(baseline, changes)
        crossed, _ = reachable_sensitive_from_untrusted(after)
        self.assertTrue(crossed)

    def test_network_change_narrowing_cidr_is_not_flagged(self):
        narrowing_diff = GENERIC_NETWORK_WIDENING_DIFF.replace(
            '-  cidr_blocks = ["10.0.0.0/16"]\n+  cidr_blocks = ["0.0.0.0/0"]',
            '-  cidr_blocks = ["0.0.0.0/0"]\n+  cidr_blocks = ["10.0.0.0/16"]',
        )
        changes, _, _ = changes_from_diff(narrowing_diff)
        self.assertEqual(len(changes), 1)
        self.assertFalse(changes[0].security_pattern_detected)
        self.assertIsNone(changes[0].effect)

    def test_generic_widening_effect_reused_on_a_resource_already_in_the_graph(self):
        # If the same synthetic resource shows up twice (e.g. re-running an
        # analysis that already added it), the effect should widen the
        # existing edge rather than duplicate the node.
        effect = make_generic_widening_effect("iam_0_test", "test", kind="iam")
        g = build_baseline_graph()
        effect(g)
        effect(g)
        matching = [n for n in g.nodes.values() if n.id == "iam_0_test"]
        self.assertEqual(len(matching), 1)


class TestLiveSnapshot(unittest.TestCase):
    def test_snapshot_reflects_current_committed_changes(self):
        snap = build_live_snapshot()
        self.assertEqual(snap["source"], "live")
        self.assertTrue(snap["boundary_crossed"])
        self.assertIn("fetched_at", snap)

    def test_snapshot_reports_drift_from_baseline(self):
        snap = build_live_snapshot()
        drifted_edges = snap["drift"]["edges_changed"]
        self.assertEqual(len(drifted_edges), 1)
        self.assertEqual(drifted_edges[0]["src"], "external_identity")
        self.assertEqual(drifted_edges[0]["dst"], "oidc_trust")
        self.assertEqual(drifted_edges[0]["before_condition"], "trusted-org/*")
        self.assertEqual(drifted_edges[0]["after_condition"], "*")

    def test_snapshot_reports_removed_edge_as_drift(self):
        def remove_oidc_edge(g):
            g.edges[:] = [
                e for e in g.edges
                if not (e.src == "external_identity" and e.dst == "oidc_trust")
            ]

        change = Change(99, "iam", "removed oidc trust edge", effect=remove_oidc_edge)
        snap = build_live_snapshot([change])

        removed = [
            d for d in snap["drift"]["edges_changed"]
            if d["src"] == "external_identity" and d["dst"] == "oidc_trust"
        ]
        self.assertEqual(len(removed), 1)
        self.assertEqual(removed[0]["before_condition"], "trusted-org/*")
        self.assertIsNone(removed[0]["after_condition"])
        self.assertFalse(snap["boundary_crossed"])


class TestApi(unittest.TestCase):
    def setUp(self):
        global DB_PATH
        self._prev_db_path = DB_PATH
        tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        tmp.close()
        DB_PATH = tmp.name
        init_db()

        app.testing = True
        self.client = app.test_client()
        self.auth_headers = {"X-API-Key": API_KEY}

    def tearDown(self):
        global DB_PATH
        os.unlink(DB_PATH)
        DB_PATH = self._prev_db_path

    def test_health_does_not_require_key(self):
        res = self.client.get("/api/health")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.get_json(), {"status": "ok"})

    def test_protected_route_rejects_missing_key(self):
        res = self.client.get("/api/changes")
        self.assertEqual(res.status_code, 401)

    def test_protected_route_rejects_wrong_key(self):
        res = self.client.get("/api/changes", headers={"X-API-Key": "wrong-key"})
        self.assertEqual(res.status_code, 401)

    def test_protected_route_accepts_correct_key(self):
        res = self.client.get("/api/changes", headers=self.auth_headers)
        self.assertEqual(res.status_code, 200)

    def test_index_page_embeds_the_current_key(self):
        res = self.client.get("/")
        self.assertEqual(res.status_code, 200)
        self.assertIn(API_KEY, res.get_data(as_text=True))

    def test_list_changes(self):
        res = self.client.get("/api/changes", headers=self.auth_headers)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(len(res.get_json()), 17)

    def test_analyze(self):
        res = self.client.post("/api/analyze", headers=self.auth_headers)
        self.assertEqual(res.status_code, 200)
        body = res.get_json()
        self.assertTrue(body["boundary_crossed"])
        self.assertEqual(body["minimum_causal_changes"][0]["id"], 7)

    def test_snapshot_endpoint(self):
        res = self.client.get("/api/snapshot", headers=self.auth_headers)
        self.assertEqual(res.status_code, 200)
        self.assertIn("drift", res.get_json())

    def test_ingest_diff_success(self):
        res = self.client.post("/api/ingest-diff", json={"diff": OIDC_WIDENING_DIFF}, headers=self.auth_headers)
        self.assertEqual(res.status_code, 200)
        body = res.get_json()
        self.assertEqual(body["source"], "diff_ingestion")
        self.assertTrue(body["boundary_crossed"])
        self.assertEqual(body["files_touched"], ["iam.tf"])
        self.assertTrue(body["parsed_changes"][0]["security_pattern_detected"])

    def test_ingest_diff_missing_body(self):
        res = self.client.post("/api/ingest-diff", json={}, headers=self.auth_headers)
        self.assertEqual(res.status_code, 400)

    def test_ingest_diff_unparseable(self):
        res = self.client.post("/api/ingest-diff", json={"diff": "nonsense"}, headers=self.auth_headers)
        self.assertEqual(res.status_code, 422)

    def test_ingest_diff_benign_change_is_safe(self):
        res = self.client.post("/api/ingest-diff", json={"diff": BENIGN_MULTI_FILE_DIFF}, headers=self.auth_headers)
        self.assertEqual(res.status_code, 200)
        self.assertFalse(res.get_json()["boundary_crossed"])

    def test_static_route_does_not_expose_source(self):
        self.assertEqual(self.client.get("/app.py").status_code, 404)
        self.assertEqual(self.client.get("/.env").status_code, 404)
        self.assertEqual(self.client.get("/styles.css").status_code, 200)
        self.assertEqual(self.client.get("/index.html").status_code, 200)

    def test_static_route_does_not_expose_database(self):
        self.assertEqual(self.client.get("/boundaryx.db").status_code, 404)

    def test_analyze_persists_and_appears_in_recent(self):
        analyze_res = self.client.post("/api/analyze", headers=self.auth_headers)
        self.assertIn("analysis_id", analyze_res.get_json())

        res = self.client.get("/api/recent", headers=self.auth_headers)
        self.assertEqual(res.status_code, 200)
        body = res.get_json()
        self.assertEqual(len(body), 1)
        self.assertEqual(body[0]["status"], "critical")
        self.assertEqual(body[0]["causal_change_id"], 7)
        self.assertEqual(body[0]["pr_tag"], "PR #1843")

    def test_ingest_diff_persists_with_diff_source(self):
        self.client.post("/api/ingest-diff", json={"diff": OIDC_WIDENING_DIFF}, headers=self.auth_headers)
        res = self.client.get("/api/recent", headers=self.auth_headers)
        body = res.get_json()
        self.assertEqual(len(body), 1)
        self.assertEqual(body[0]["source"], "diff_ingestion")

    def test_recent_respects_limit_and_orders_newest_first(self):
        for _ in range(3):
            self.client.post("/api/analyze", headers=self.auth_headers)
        res = self.client.get("/api/recent?limit=2", headers=self.auth_headers)
        body = res.get_json()
        self.assertEqual(len(body), 2)
        self.assertGreater(body[0]["id"], body[1]["id"])

    def test_report_endpoint_returns_stored_result(self):
        analyze_res = self.client.post("/api/analyze", headers=self.auth_headers)
        analysis_id = analyze_res.get_json()["analysis_id"]
        res = self.client.get(f"/api/report/{analysis_id}", headers=self.auth_headers)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.get_json()["minimum_causal_changes"][0]["id"], 7)

    def test_report_endpoint_404_for_unknown_id(self):
        res = self.client.get("/api/report/999999", headers=self.auth_headers)
        self.assertEqual(res.status_code, 404)

    def test_recent_requires_api_key(self):
        res = self.client.get("/api/recent")
        self.assertEqual(res.status_code, 401)


if __name__ == "__main__":
    if "--test" in sys.argv:
        sys.argv = [sys.argv[0]]
        unittest.main()
    elif "--demo" in sys.argv:
        result = run_analysis()
        print(json.dumps(result, indent=2))
        print()
        print(f"{result['changes_submitted']} changes submitted")
        print(f"Before state safe: {result['before_state_safe']}")
        print(f"After state safe:  {result['after_state_safe']}")
        if result["minimum_causal_changes"]:
            c = result["minimum_causal_changes"][0]
            print(f"\nMinimum causal change: #{c['id']} — {c['description']}")
            print(f"Blast radius: {result['blast_radius']}")
            print(f"Remediation: {result['remediation']['action']}")
        else:
            print("\nNo boundary crossing found.")
    else:

        print(f" * API key for this session: {API_KEY}")
        print("   (auto-injected into the page at http://127.0.0.1:5000 — no setup needed)")
        app.run(debug=True, use_reloader=False, threaded=True, port=5000)