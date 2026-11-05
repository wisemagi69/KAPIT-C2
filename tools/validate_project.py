"""Validate integrated planning/task/state links without running application code."""

from __future__ import annotations

import argparse
import csv
import hashlib
import re
import sys
from pathlib import Path

from ai_common import (
    ProjectError, Report, check_markdown_links, print_report, read_json,
    root_path, safe_path, skill_key, validate_glob, validate_project,
)


STATES = {"backlog", "ready", "in_progress", "in_review", "changes_requested", "blocked", "done"}
REQUIRED_DOCS = (
    "source-audit", "requirements", "module-catalog", "architecture", "database-design",
    "api-contract", "ui-plan", "implementation-plan", "test-plan", "resource-plan",
    "risk-register", "deployment-runbook",
)


def check_graph(tasks: list[dict], requirements: list[dict], state: dict,
                agent_ids: set[str], skill_refs: set[str]) -> list[str]:
    """Check cross-record behavior: approval, graph, traceability and completion claims."""
    errors = []
    by_id = {}
    req_ids = set()
    for row in requirements:
        if not re.fullmatch(r"(?:REQ|SEC|SYNC|UX|OPS|DEV)-\d{3}", row.get("id", "")):
            errors.append("invalid requirement ID")
        if row.get("id") in req_ids:
            errors.append(f"duplicate requirement ID: {row['id']}")
        req_ids.add(row.get("id"))
    for task in tasks:
        task_id = task.get("id")
        if not isinstance(task_id, str) or not re.fullmatch(r"(?:BOOT|TASK)-\d{3}", task_id):
            errors.append("invalid canonical task ID")
            continue
        if task_id in by_id:
            errors.append(f"duplicate task ID: {task_id}")
        by_id[task_id] = task
    approvals = state.get("milestone_approvals", {})
    for task_id, task in by_id.items():
        status = task.get("status")
        if status not in STATES:
            errors.append(f"{task_id}: invalid task status")
        if task.get("owner") not in agent_ids or task.get("reviewer") not in agent_ids:
            errors.append(f"{task_id}: unknown owner/reviewer")
        if task.get("owner") == task.get("reviewer"):
            errors.append(f"{task_id}: owner cannot review own task")
        linked = task.get("requirement_ids", [])
        if not linked or len(linked) != len(set(linked)) or any(r not in req_ids for r in linked):
            errors.append(f"{task_id}: missing, duplicate or unknown linked requirement")
        if not task.get("source_refs"):
            errors.append(f"{task_id}: missing source references")
        if any(ref not in skill_refs for ref in task.get("skills", [])) or not task.get("skills"):
            errors.append(f"{task_id}: missing or unknown skill version")
        if not task.get("acceptance_criteria") or not task.get("objective"):
            errors.append(f"{task_id}: missing concrete objective/acceptance")
        if not task.get("verification_commands") and not task.get("verification_procedure"):
            errors.append(f"{task_id}: missing verification method")
        attempts = task.get("attempt_count")
        if type(attempts) is not int or attempts < 0 or attempts > state.get("max_repair_attempts", 2):
            errors.append(f"{task_id}: invalid repair count")
        approved = approvals.get(task.get("milestone")) is True
        if task.get("approved") is not approved:
            errors.append(f"{task_id}: task approval disagrees with milestone")
        if approved and not task.get("approval_ref"):
            errors.append(f"{task_id}: missing approval provenance")
        if status in {"ready", "in_progress", "in_review", "changes_requested", "done"} and not approved:
            errors.append(f"{task_id}: unapproved task cannot execute or complete")
        if status == "done" and not task.get("artifacts"):
            errors.append(f"{task_id}: done requires actual evidence/artifacts")
        if status == "blocked" and not task.get("blocker"):
            errors.append(f"{task_id}: blocked needs exact blocker")
        deps = task.get("dependencies", [])
        if len(deps) != len(set(deps)) or task_id in deps:
            errors.append(f"{task_id}: duplicate/self dependency")
        for dependency in deps:
            if dependency not in by_id:
                errors.append(f"{task_id}: missing dependency {dependency}")
            elif status == "ready" and by_id[dependency].get("status") != "done":
                errors.append(f"{task_id}: ready dependency is not done")
    visited, visiting = set(), set()

    def visit(task_id):
        if task_id in visiting:
            errors.append(f"dependency cycle at {task_id}")
            return
        if task_id in visited or task_id not in by_id:
            return
        visiting.add(task_id)
        for dependency in by_id[task_id].get("dependencies", []):
            visit(dependency)
        visiting.remove(task_id)
        visited.add(task_id)

    for task_id in by_id:
        visit(task_id)
    for row in requirements:
        for task_id in (item.strip() for item in row.get("task_ids", "").split(";")):
            if not task_id or task_id not in by_id:
                errors.append(f"{row['id']}: unknown or missing traceability task {task_id}")
            elif row["id"] not in by_id[task_id].get("requirement_ids", []):
                errors.append(f"{row['id']}: reciprocal task link missing")
    for field, status in (("completed_tasks", "done"), ("in_review_tasks", "in_review"), ("blocked_tasks", "blocked")):
        actual = set(state.get(field, []))
        expected = {task_id for task_id, task in by_id.items() if task.get("status") == status}
        if actual != expected:
            errors.append(f"state {field} disagrees with canonical tasks")
    return errors


def check_all(root: Path) -> Report:
    report = validate_project(root)
    try:
        for name in REQUIRED_DOCS:
            safe_path(root, f"docs/{name}.md", exists=True)
        agents = read_json(root, "ai/registry/agents.yaml")["agents"]
        skills = read_json(root, "ai/registry/skills.yaml")["skills"]
        state = read_json(root, "ai/state/orchestrator-state.yaml")
        snapshot = read_json(root, "ai/state/source-snapshot.json")
        for path, digest in snapshot["files"].items():
            file = safe_path(root, path, exists=True)
            if hashlib.sha256(file.read_bytes()).hexdigest() != digest:
                report.error(f"Source hash changed; reconcile audit and snapshot: {path}")
        tasks = [read_json(root, path.relative_to(root).as_posix()) for path in sorted((root / "ai/tasks").glob("*.yaml"))]
        with safe_path(root, "docs/traceability.csv", exists=True).open(encoding="utf-8-sig", newline="") as stream:
            requirements = list(csv.DictReader(stream))
        required_columns = {"id", "description", "source_ref", "evidence_kind", "priority", "module_ids",
                            "acceptance_criteria", "implementation_status", "task_ids", "test_ids", "approval_state", "verification_status"}
        if not requirements or not required_columns.issubset(requirements[0]):
            raise ProjectError("traceability missing required columns/records")
        for row in requirements:
            if any(not row.get(column, "").strip() for column in required_columns):
                report.error(f"{row.get('id')}: empty required traceability field")
            modules = [item.strip() for item in row["module_ids"].split(";")]
            if any(not re.fullmatch(r"M(?:0[1-9]|1[0-4])", module)
                   and not (row["id"].startswith("DEV-") and module == "Developer-infrastructure")
                   for module in modules):
                report.error(f"{row['id']}: unknown module")
            if row["priority"] not in {"P0", "P1", "P2"}:
                report.error(f"{row['id']}: unknown priority")
            for test_id in (item.strip() for item in row["test_ids"].split(";")):
                if test_id not in (root / "docs/test-plan.md").read_text(encoding="utf-8"):
                    report.error(f"{row['id']}: planned test {test_id} missing from test plan")
        report.errors.extend(check_graph(tasks, requirements, state, {a["id"] for a in agents},
                                        {s["id"] + "@" + s["version"] for s in skills}))
        for task in tasks:
            for pattern in task["allowed_paths"]:
                validate_glob(pattern, allowed=True)
            for pattern in task["forbidden_paths"]:
                validate_glob(pattern, allowed=False)
            for artifact in task["artifacts"]:
                safe_path(root, artifact, exists=True)
            if task["status"] == "done" and (not task.get("review_evidence") or not task.get("verification_evidence")):
                report.error(f"{task['id']}: done requires review and verification evidence")
            for evidence in (task.get("review_evidence"), task.get("verification_evidence")):
                if evidence:
                    safe_path(root, evidence, exists=True)
        for folder in ("docs", "ai"):
            for path in (root / folder).rglob("*.md"):
                relative = path.relative_to(root).as_posix()
                check_markdown_links(root, relative, path.read_text(encoding="utf-8-sig"))
        for relative in ("AGENTS.md", "README.md", "tools/README.md"):
            file = safe_path(root, relative, exists=True)
            check_markdown_links(root, relative, file.read_text(encoding="utf-8-sig"))
        readable = (root / "docs/requirements.md").read_text(encoding="utf-8")
        readable_ids = set(re.findall(r"(?:REQ|SEC|SYNC|UX|OPS|DEV)-\d{3}", readable))
        if readable_ids != {row["id"] for row in requirements}:
            report.error("Readable requirement IDs disagree with traceability.csv")
        report.counts.update(tasks=len(tasks), requirements=len(requirements), diagrams=len(list((root / "docs/diagrams").glob("*.mmd"))))
    except (ProjectError, OSError, KeyError, TypeError, ValueError) as exc:
        report.error(str(exc))
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", help="Existing project root (default: this repository)")
    args = parser.parse_args(argv)
    try:
        return print_report(check_all(root_path(args.root)), "Integrated bootstrap")
    except (ProjectError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
