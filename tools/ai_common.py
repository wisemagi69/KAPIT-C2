"""Repository-local validation primitives. Uses only the Python standard library."""

from __future__ import annotations

import fnmatch
import json
import os
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import unquote, urlsplit


PROJECT_ROOT = Path(__file__).resolve().parent.parent
NAME_RE = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*\Z")
VERSION_RE = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z")
RESERVED_RE = re.compile(r"(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?\Z", re.I)
SKILL_SECTIONS = (
    "Purpose", "Triggers", "When not to use", "Prerequisites", "Source references",
    "Inputs", "Procedure", "Outputs", "Invariants", "Examples", "Verification",
    "Failure handling", "Escalation", "Limitations",
)
AGENT_SECTIONS = (
    "Purpose", "Modules", "Source references", "Inputs", "Skills", "Permitted tools",
    "Allowed files", "Prohibited actions", "Outputs", "Completion tests", "Escalation",
    "Reviewer", "Handoff",
)
CASE_KINDS = {"positive", "incorrect_trigger", "failure", "scope_boundary", "injection"}
REQUIRED_KINDS = CASE_KINDS - {"injection"}


class ProjectError(ValueError):
    """A malformed artifact or unsafe input, safe to show without a traceback."""


@dataclass
class Report:
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=dict)

    def error(self, message: str) -> None:
        self.errors.append(message)

    def warn(self, message: str) -> None:
        self.warnings.append(message)

    @property
    def ok(self) -> bool:
        return not self.errors


def valid_name(value: object) -> bool:
    return isinstance(value, str) and 1 <= len(value) < 64 and bool(NAME_RE.fullmatch(value))


def skill_key(value: object) -> tuple[str, str]:
    if not isinstance(value, str) or value.count("@") != 1:
        raise ProjectError("skill references must use id@major.minor.patch")
    name, version = value.split("@")
    if not valid_name(name) or not VERSION_RE.fullmatch(version):
        raise ProjectError("skill references must use safe names and exact id@major.minor.patch versions")
    return name, version


def _safe_parts(relative: str, *, glob: bool = False, parents: bool = False) -> list[str]:
    if not isinstance(relative, str) or not relative or relative != relative.strip():
        raise ProjectError("path must be a nonempty relative string without surrounding whitespace")
    if "\\" in relative or relative.startswith("/") or re.match(r"^[A-Za-z]:", relative):
        raise ProjectError("use repository-relative paths with forward slashes; absolute paths are forbidden")
    if any(ord(c) < 32 or ord(c) == 127 for c in relative) or any(c in relative for c in ':<>|"'):
        raise ProjectError("path contains unsafe characters")
    parts = relative.rstrip("/").split("/")
    for part in parts:
        if not part or part == "." or (part == ".." and not parents):
            raise ProjectError("empty path components, dot paths and traversal are forbidden")
        if part == ".." and parents:
            continue
        if part.endswith((".", " ")) or RESERVED_RE.fullmatch(part):
            raise ProjectError("path contains a reserved or ambiguous filename")
        if not glob and any(c in part for c in "*?[]"):
            raise ProjectError("wildcards are forbidden in file paths")
    return parts


def root_path(root: str | Path | None = None) -> Path:
    path = Path(root) if root is not None else PROJECT_ROOT
    if not path.is_dir():
        raise ProjectError("project root must be an existing directory")
    absolute = path.absolute()
    if any(_is_link(parent) for parent in (absolute, *absolute.parents)):
        raise ProjectError("project root or its ancestors cannot be symlinks or junctions")
    return path.resolve()


def _is_link(path: Path) -> bool:
    if path.is_symlink():
        return True
    try:
        info = path.lstat()
    except FileNotFoundError:
        return False
    return bool(getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))


def safe_path(root: Path, relative: str, *, exists: bool = False) -> Path:
    parts = _safe_parts(relative)
    candidate = root.joinpath(*parts)
    current = root
    for part in parts:
        current = current / part
        if _is_link(current):
            raise ProjectError("symlink/junction paths are forbidden")
    try:
        candidate.resolve().relative_to(root.resolve())
    except ValueError as exc:
        raise ProjectError("path escapes the project root") from exc
    if exists and not candidate.exists():
        raise ProjectError(f"missing repository artifact: {relative}")
    return candidate


def mkdir_safe(root: Path, relative: str, *, exclusive: bool = False) -> Path:
    candidate = safe_path(root, relative)
    parts = _safe_parts(relative)
    current = root
    for index, part in enumerate(parts):
        current = current / part
        last = index == len(parts) - 1
        current.mkdir(exist_ok=not (last and exclusive))
        safe_path(root, current.relative_to(root).as_posix(), exists=True)
        if not current.is_dir():
            raise ProjectError("destination parent is not a directory")
    return candidate


def write_exclusive(root: Path, relative: str, content: str) -> None:
    """Never overwrite; recheck parents before opening with exclusive creation."""
    path = safe_path(root, relative)
    if not path.parent.is_dir():
        raise ProjectError("output parent directory must exist")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
        stream.write(content)


def _unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ProjectError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def read_json(root: Path, relative: str) -> dict:
    path = safe_path(root, relative, exists=True)
    if not path.is_file():
        raise ProjectError(f"expected a regular file: {relative}")
    try:
        result = json.loads(
            path.read_text(encoding="utf-8-sig"), object_pairs_hook=_unique_object,
            parse_constant=lambda value: (_ for _ in ()).throw(ProjectError("nonfinite JSON values are forbidden")),
        )
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise ProjectError(f"invalid JSON-compatible YAML/JSON: {relative}") from exc
    if not isinstance(result, dict):
        raise ProjectError(f"expected a JSON object: {relative}")
    if type(result.get("schema_version")) is not int or result["schema_version"] != 1:
        raise ProjectError(f"unsupported schema_version in {relative}; expected 1")
    return result


def string_list(value: object, label: str, *, empty: bool = True) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(v, str) or not v.strip() for v in value):
        raise ProjectError(f"{label} must be a list of nonempty strings")
    if not empty and not value:
        raise ProjectError(f"{label} must not be empty")
    if len(value) != len(set(value)):
        raise ProjectError(f"{label} contains duplicate entries")
    return value


def validate_glob(pattern: str, *, allowed: bool) -> None:
    parts = _safe_parts(pattern, glob=True)
    if allowed and any(c in parts[0] for c in "*?["):
        raise ProjectError("allowed paths need a concrete first directory or filename; blanket ownership is forbidden")
    if allowed and any(part.casefold() in {".git", ".codex", ".agents", ".aws"}
                       or (part.casefold().startswith(".env") and part.casefold() != ".env.example")
                       for part in parts):
        raise ProjectError("agent ownership cannot grant writes to protected configuration or secret paths")
    # Check the concrete prefix for existing symlinks separately at the registry root.


def owns(agent: dict, relative: str) -> bool:
    # Windows aliases are the same file: a differently cased forbidden path must
    # not pass a broad allowed glob. POSIX ownership retains case distinctions.
    if os.name == "nt":
        relative = relative.casefold()
    def matches(pattern: str) -> bool:
        if os.name == "nt":
            pattern = pattern.casefold()
        return fnmatch.fnmatchcase(relative, pattern) or relative == pattern.rstrip("/")

    return any(matches(p) for p in agent["allowed_paths"]) and not any(
        matches(p) for p in agent["forbidden_paths"]
    )


def parse_frontmatter(content: str) -> tuple[dict[str, str], str]:
    lines = content.splitlines()
    if not lines or lines[0] != "---":
        raise ProjectError("SKILL.md must start with YAML frontmatter")
    try:
        end = lines.index("---", 1)
    except ValueError as exc:
        raise ProjectError("unclosed SKILL.md frontmatter") from exc
    values = {}
    for line in lines[1:end]:
        match = re.fullmatch(r"(name|description):[ \t]+(.+)", line)
        if not match or match[1] in values:
            raise ProjectError("frontmatter supports exactly one name and description scalar; other fields are registry-owned")
        raw = match[2].strip()
        if raw.startswith('"'):
            try:
                value = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise ProjectError("double-quoted frontmatter must use JSON string escaping") from exc
        elif raw.startswith("'"):
            if not raw.endswith("'") or re.search(r"(?<!')'(?!')", raw[1:-1]):
                raise ProjectError("invalid single-quoted YAML string")
            value = raw[1:-1].replace("''", "'")
        else:
            if raw[0] in "[{&*!>|%@`#" or ": " in raw or " #" in raw or raw.lower() in {"true", "false", "null", "~", "yes", "no", "on", "off", "y", "n"} or re.fullmatch(r"[-+]?(?:[0-9][0-9_.eE+-]*|0[xX][0-9a-fA-F]+)|[-+]?\.(?:inf|nan)", raw, re.I):
                raise ProjectError("ambiguous YAML scalar; use a JSON-quoted string")
            value = raw
        if not isinstance(value, str) or not value.strip() or any(ord(c) < 32 or ord(c) == 127 for c in value):
            raise ProjectError("frontmatter values must be nonempty single-line strings")
        values[match[1]] = value
    if set(values) != {"name", "description"}:
        raise ProjectError("frontmatter needs exactly name and description")
    if not valid_name(values["name"]):
        raise ProjectError("invalid skill name; use fewer than 64 lowercase letters, digits and single hyphens")
    if len(values["description"]) > 1024:
        raise ProjectError("description must be at most 1024 characters")
    return values, "\n".join(lines[end + 1:])


def sections(content: str, required: tuple[str, ...]) -> dict[str, str]:
    headings = list(re.finditer(r"(?m)^##[ \t]+(.+?)[ \t]*$", content))
    result = {}
    for index, heading in enumerate(headings):
        name = heading[1].rstrip(" #")
        if name in result:
            raise ProjectError(f"duplicate section: {name}")
        end = headings[index + 1].start() if index + 1 < len(headings) else len(content)
        result[name] = content[heading.end():end].strip()
    missing = [name for name in required if not result.get(name)]
    if missing:
        raise ProjectError("missing or empty sections: " + ", ".join(missing))
    return result


def markdown_targets(content: str) -> list[str]:
    # Code fences contain examples, not active document references.
    cleaned = []
    fence = None
    for line in content.splitlines():
        match = re.match(r"^\s*(`{3,}|~{3,})", line)
        if match:
            if fence is None:
                fence = match[1][0]
            elif match[1][0] == fence:
                fence = None
            continue
        if fence is None:
            cleaned.append(line)
    text = "\n".join(cleaned)
    targets = [m[1].strip("<>") for m in re.finditer(
        r"!?\[[^\]\n]*\]\(\s*(<[^>\n]+>|[^\s)]+)(?:\s+['\"][^\n]*?['\"])?\s*\)", text
    )]
    definitions = {}
    for match in re.finditer(r"(?m)^\s{0,3}\[([^\]\n]+)\]:\s*(<[^>\n]+>|\S+)", text):
        label = match[1].casefold()
        if label in definitions:
            raise ProjectError("duplicate Markdown reference definition")
        definitions[label] = match[2].strip("<>")
        targets.append(definitions[label])
    for match in re.finditer(r"(?<!!)\[([^\]\n]+)\]\[([^\]\n]*)\]", text):
        if (match[2] or match[1]).casefold() not in definitions:
            raise ProjectError("undefined Markdown reference link")
    return targets


def _anchors(content: str) -> set[str]:
    result = set()
    counts = {}
    for match in re.finditer(r"(?m)^#{1,6}\s+(.+?)(?:\s+#+)?\s*$", content):
        slug = re.sub(r"[^\w\- ]", "", match[1].lower()).replace(" ", "-")
        index = counts.get(slug, 0)
        counts[slug] = index + 1
        result.add(f"{slug}-{index}" if index else slug)
    result.update(re.findall(r'<a\s+(?:name|id)=["\']([^"\']+)["\']', content))
    return result


def check_markdown_links(root: Path, relative: str, content: str) -> None:
    source = safe_path(root, relative, exists=True)
    for target in markdown_targets(content):
        parsed = urlsplit(target)
        if parsed.scheme in {"http", "https", "mailto"}:
            if parsed.scheme in {"http", "https"} and not parsed.netloc:
                raise ProjectError("HTTP Markdown links need an absolute host")
            continue  # Only syntax is checked; no network request or availability claim.
        if parsed.scheme or parsed.netloc or parsed.query:
            raise ProjectError("unsupported or unsafe Markdown link scheme/path")
        raw = unquote(parsed.path)
        if not raw:
            destination = source
        else:
            parts = _safe_parts(raw, parents=True)
            normalized = source.parent
            for part in parts:
                normalized = normalized.parent if part == ".." else normalized / part
                if _is_link(normalized):
                    raise ProjectError("symlink/junction components in Markdown references are forbidden")
                try:
                    normalized.relative_to(root)
                except ValueError as exc:
                    raise ProjectError("Markdown link escapes project root") from exc
            try:
                local = normalized.relative_to(root).as_posix()
            except ValueError as exc:
                raise ProjectError("Markdown link escapes project root") from exc
            destination = safe_path(root, local, exists=True)
        if parsed.fragment and destination.suffix.lower() == ".md":
            if unquote(parsed.fragment) not in _anchors(destination.read_text(encoding="utf-8-sig")):
                raise ProjectError("Markdown link has an unknown local heading anchor")


def check_prohibited(content: str, *, reviewed: bool) -> None:
    if re.search(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|\bgh[pousr]_[A-Za-z0-9]{30,}|\bsk-(?:live|proj)-[A-Za-z0-9_-]{20,}", content):
        raise ProjectError("possible credential/private key content; remove sensitive material before review")
    if reviewed and re.search(r"\bTODO\b|\bTBD\b|\{\{[a-z_]+\}\}", content):
        raise ProjectError("reviewed skills cannot contain unfinished scaffold markers")
    # This is a narrow lint, not a guarantee against semantic prompt injection.
    if re.search(r"(?im)^\s*(?:\d+[.)]\s*)?(?:ignore (?:all )?(?:previous|system) instructions|disable (?:authentication|authorization))\b", content):
        raise ProjectError("prohibited instruction directive in skill/agent text")


def load_cases(root: Path, skill: dict) -> list[dict]:
    relative = f"{skill['path'].rstrip('/')}/tests/scenarios.json"
    data = read_json(root, relative)
    cases = data.get("cases")
    if not isinstance(cases, list) or not cases:
        raise ProjectError("scenarios.json needs a nonempty cases list")
    seen = set()
    kinds = set()
    manual = False
    for case in cases:
        if not isinstance(case, dict) or not valid_name(case.get("id")) or case["id"] in seen:
            raise ProjectError("scenario IDs must be unique safe names")
        seen.add(case["id"])
        kind, mode = case.get("kind"), case.get("mode")
        if not isinstance(kind, str) or kind not in CASE_KINDS or mode not in {"manual", "executable"}:
            raise ProjectError("scenario kind/mode is invalid")
        kinds.add(kind)
        if not isinstance(case.get("request"), str) or not case["request"].strip():
            raise ProjectError("each scenario needs a nonempty request")
        string_list(case.get("expected"), "scenario expected outcomes", empty=False)
        if mode == "manual":
            manual = True
            if "assertion" in case:
                raise ProjectError("manual scenarios cannot include executable assertions")
        else:
            validate_assertion(root, case.get("assertion"))
    if not REQUIRED_KINDS.issubset(kinds):
        raise ProjectError("scenarios must cover positive, incorrect_trigger, failure and scope_boundary")
    if "security" in skill.get("id", "") or "authorization" in skill.get("id", ""):
        if "injection" not in kinds:
            raise ProjectError("security-sensitive skills need a synthetic injection/leakage scenario")
    if skill.get("state") == "validated" and not manual:
        raise ProjectError("validated skills need independent manual behavioral review, not assertions alone")
    return cases


def validate_assertion(root: Path, assertion: object) -> None:
    if not isinstance(assertion, dict):
        raise ProjectError("executable scenario needs an assertion object")
    kind = assertion.get("type")
    if kind not in {"file_contains", "file_not_contains", "json_equals"}:
        raise ProjectError("unsupported assertion; only file_contains, file_not_contains and json_equals are executable")
    if "command" in assertion or "shell" in assertion or "script" in assertion:
        raise ProjectError("arbitrary commands/scripts are forbidden in assertions")
    safe_path(root, assertion.get("path"))
    if kind == "file_contains":
        string_list(assertion.get("contains"), "assertion contains", empty=False)
    elif kind == "file_not_contains":
        string_list(assertion.get("forbidden"), "assertion forbidden", empty=False)
    elif not isinstance(assertion.get("pointer"), str) or (
        assertion["pointer"] and not assertion["pointer"].startswith("/")
    ) or "expected" not in assertion:
        raise ProjectError("json_equals needs an RFC 6901 pointer and expected value")


def execute_assertion(root: Path, assertion: dict) -> tuple[bool, Path]:
    """Read-only comparisons; never eval, import or invoke fixture-supplied code."""
    validate_assertion(root, assertion)
    path = safe_path(root, assertion["path"], exists=True)
    if not path.is_file():
        raise ProjectError("assertion artifact must be a regular file")
    content = path.read_text(encoding="utf-8-sig")
    kind = assertion["type"]
    if kind == "file_contains":
        return all(value in content for value in assertion["contains"]), path
    if kind == "file_not_contains":
        return all(value not in content for value in assertion["forbidden"]), path
    try:
        data = json.loads(content, object_pairs_hook=_unique_object,
                          parse_constant=lambda value: (_ for _ in ()).throw(ProjectError("nonfinite JSON values are forbidden")))
        pointer = assertion["pointer"]
        if pointer:
            for segment in pointer[1:].split("/"):
                if re.search(r"~(?![01])", segment):
                    raise ProjectError("invalid JSON pointer escape")
                key = segment.replace("~1", "/").replace("~0", "~")
                if isinstance(data, list):
                    if not key.isdigit() or (len(key) > 1 and key[0] == "0"):
                        return False, path
                    data = data[int(key)]
                elif isinstance(data, dict):
                    data = data[key]
                else:
                    return False, path
        # JSON booleans and numbers have distinct types despite Python equality.
        expected = assertion["expected"]
        return json.dumps(data, sort_keys=True) == json.dumps(expected, sort_keys=True), path
    except (json.JSONDecodeError, KeyError, IndexError):
        return False, path


def load_manual_evidence(root: Path, relative: str, skill: dict, cases: list[dict]) -> dict:
    data = read_json(root, relative)
    if data.get("skill_id") != skill["id"] or data.get("version") != skill["version"]:
        raise ProjectError("evidence must identify this exact skill version")
    reviewer = data.get("reviewer")
    if not isinstance(reviewer, str) or reviewer not in skill["reviewers"] or reviewer == skill["owner"]:
        raise ProjectError("manual evidence reviewer must be a registered independent reviewer for this skill")
    expected = {c["id"] for c in cases if c["mode"] == "manual"}
    entries = data.get("cases")
    if not isinstance(entries, list):
        raise ProjectError("manual evidence cases must be a list")
    result = {}
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("id"), str) or entry["id"] not in expected or entry["id"] in result:
            raise ProjectError("manual evidence case IDs must uniquely match manual scenarios")
        status = entry.get("result")
        if status not in {"passed", "failed", "not_run"}:
            raise ProjectError("manual evidence results must be passed, failed or not_run")
        if not isinstance(entry.get("notes"), str) or not entry["notes"].strip():
            raise ProjectError("manual evidence needs notes describing the observation or blocker")
        artifact = entry.get("artifact")
        if status in {"passed", "failed"}:
            path = safe_path(root, artifact, exists=True)
            if not path.is_file() or not path.stat().st_size:
                raise ProjectError("completed manual cases need a nonempty regular artifact file")
            normalized = path.relative_to(root).as_posix()
            if normalized == relative or path.name in {"SKILL.md", "scenarios.json"} or normalized.startswith("ai/registry/"):
                raise ProjectError("manual behavioral evidence cannot be the skill, registry, scenario definition or evidence file itself")
        elif artifact is not None:
            safe_path(root, artifact, exists=True)
        result[entry["id"]] = entry
    return {"reviewer": reviewer, "cases": result}


def _entries(data: dict, field_name: str, report: Report) -> list[dict]:
    items = data.get(field_name)
    if not isinstance(items, list):
        report.error(f"{field_name} must be a list")
        return []
    if any(not isinstance(item, dict) for item in items):
        report.error(f"{field_name} entries must be objects")
        return [item for item in items if isinstance(item, dict)]
    return items


def validate_project(root: Path, *, focus: str = "all") -> Report:
    """Validate registries and cross-references without modifying files or launching tools."""
    report = Report()
    datasets = {}
    for name, relative in (
        ("agents", "ai/registry/agents.yaml"), ("skills", "ai/registry/skills.yaml"),
        ("capabilities", "ai/runtime/capabilities.yaml"),
    ):
        try:
            datasets[name] = read_json(root, relative)
        except (ProjectError, OSError) as exc:
            report.error(f"{relative}: {exc}")
    if len(datasets) != 3:
        return report

    adapters = {}
    for adapter in _entries(datasets["capabilities"], "adapters", report):
        try:
            identifier = adapter.get("id")
            if not valid_name(identifier) or identifier in adapters:
                raise ProjectError("adapter IDs must be unique safe names")
            path = safe_path(root, adapter.get("path"), exists=True)
            if not path.is_file():
                raise ProjectError("adapter path must be a regular file")
            if adapter.get("status") != "session-tested":
                raise ProjectError("assigned adapters must have session-tested status")
            adapters[identifier] = adapter
        except (ProjectError, OSError) as exc:
            report.error(f"adapter: {exc}")

    agents = {}
    known_tools = datasets["capabilities"].get("tools")
    if known_tools is not None and not isinstance(known_tools, dict):
        report.error("capabilities tools must be an object of tool names and availability descriptions")
        known_tools = None
    for agent in _entries(datasets["agents"], "agents", report):
        identifier = agent.get("id")
        try:
            if not valid_name(identifier) or identifier in agents:
                raise ProjectError("agent IDs must be unique safe names")
            if not isinstance(agent.get("name"), str) or not agent["name"].strip():
                raise ProjectError("agent needs a display name")
            for key in ("modules", "skills", "allowed_paths", "forbidden_paths", "tools"):
                string_list(agent.get(key), f"agent {key}", empty=key == "forbidden_paths")
            for reference in agent["skills"]:
                skill_key(reference)
            if known_tools is not None:
                for tool in agent["tools"]:
                    capability = known_tools.get(tool)
                    if not isinstance(capability, str) or not capability.strip() or re.match(r"(?i)^(?:unavailable|absent|blocked|untested|unsupported)\b", capability):
                        raise ProjectError("agent names an unavailable or unrecorded tool")
            for key in ("allowed_paths", "forbidden_paths"):
                for pattern in agent[key]:
                    validate_glob(pattern, allowed=key == "allowed_paths")
                    prefix = re.split(r"[\*?\[]", pattern)[0].rstrip("/")
                    if prefix:
                        safe_path(root, prefix)
            safe_path(root, agent.get("definition"), exists=True)
            if agent.get("adapter") not in adapters:
                raise ProjectError("agent adapter is missing or unsupported")
            if not valid_name(agent.get("reviewer")) or agent["reviewer"] == identifier:
                raise ProjectError("agent needs a distinct reviewer ID")
            agents[identifier] = agent
        except (ProjectError, OSError, TypeError) as exc:
            report.error(f"agent {identifier if isinstance(identifier, str) else '<invalid id>'}: {exc}")

    skills = {}
    ids = set()
    paths = set()
    for skill in _entries(datasets["skills"], "skills", report):
        identifier = skill.get("id")
        try:
            if not valid_name(identifier) or identifier in ids:
                raise ProjectError("skill IDs must be unique safe names")
            version = skill.get("version")
            if not isinstance(version, str) or not VERSION_RE.fullmatch(version):
                raise ProjectError("skill version must be exact major.minor.patch")
            if skill.get("state") not in {"draft", "reviewed", "validated", "deprecated"}:
                raise ProjectError("unsupported skill lifecycle state")
            path = safe_path(root, skill.get("path"), exists=True)
            if not path.is_dir() or path.name != identifier or path in paths:
                raise ProjectError("skill path must be a unique package directory matching its ID")
            string_list(skill.get("reviewers"), "skill reviewers", empty=False)
            string_list(skill.get("dependencies"), "skill dependencies")
            string_list(skill.get("evidence"), "skill evidence")
            for dependency in skill["dependencies"]:
                skill_key(dependency)
            owner = skill.get("owner")
            if not isinstance(owner, str) or owner not in agents:
                raise ProjectError("skill owner must be a registered agent")
            if not owns(agents[owner], path.relative_to(root).as_posix() + "/SKILL.md"):
                raise ProjectError("skill owner does not have permitted file ownership")
            if any(reviewer not in agents or reviewer == owner for reviewer in skill["reviewers"]):
                raise ProjectError("skill reviewers must be registered and distinct from owner")
            if not isinstance(skill.get("compatibility"), (str, dict)) or not skill["compatibility"]:
                raise ProjectError("skill needs compatibility notes")
            history = skill.get("change_history")
            if not isinstance(history, list) or not history:
                raise ProjectError("skill needs nonempty change_history")
            history_versions = set()
            for change in history:
                if not isinstance(change, dict) or not isinstance(change.get("version"), str) or not VERSION_RE.fullmatch(change["version"]):
                    raise ProjectError("invalid change-history version")
                if change["version"] in history_versions:
                    raise ProjectError("duplicate change-history version")
                history_versions.add(change["version"])
                if not isinstance(change.get("date"), str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", change["date"]) or not isinstance(change.get("summary"), str) or not change["summary"].strip():
                    raise ProjectError("history entries need ISO date and nonempty summary")
            if version not in history_versions:
                raise ProjectError("current version is missing from change_history")
            for evidence in skill["evidence"]:
                safe_path(root, evidence, exists=True)
            ids.add(identifier)
            paths.add(path)
            skills[(identifier, version)] = skill
        except (ProjectError, OSError, TypeError) as exc:
            report.error(f"skill {identifier if isinstance(identifier, str) else '<invalid id>'}: {exc}")

    for candidate in _entries(datasets["skills"], "candidates", report):
        if not valid_name(candidate.get("id")) or candidate["id"] in ids:
            report.error("candidate skill ID is unsafe, duplicated or already registered")
        else:
            ids.add(candidate["id"])
        if any(not isinstance(candidate.get(key), str) or not candidate[key].strip() for key in ("reason", "milestone")):
            report.error("skill candidates need a reason and milestone")

    for identifier, agent in agents.items():
        if agent["reviewer"] not in agents:
            report.error(f"agent {identifier}: reviewer is not registered")
        for reference in agent["skills"]:
            skill = skills.get(skill_key(reference))
            if skill is None or skill["state"] in {"draft", "deprecated"}:
                report.error(f"agent {identifier}: assigned skill {reference} is missing, draft or deprecated")
            elif skill["state"] == "reviewed":
                report.warn(f"assigned skill {reference} is reviewed; behavioral validation remains pending")
        if focus in {"all", "agents"}:
            try:
                content = safe_path(root, agent["definition"], exists=True).read_text(encoding="utf-8-sig")
                parts = sections(content, AGENT_SECTIONS)
                check_markdown_links(root, agent["definition"], content)
                check_prohibited(content, reviewed=True)
                if any(reference not in parts["Skills"] for reference in agent["skills"]):
                    raise ProjectError("definition Skills section does not name each assigned exact version")
            except (ProjectError, OSError, UnicodeError) as exc:
                report.error(f"agent {identifier} definition: {exc}")

    graph = {}
    for key, skill in skills.items():
        graph[key] = [skill_key(reference) for reference in skill["dependencies"]]
        for dependency in graph[key]:
            target = skills.get(dependency)
            if target is None or target["state"] == "deprecated":
                report.error(f"skill {skill['id']}: missing/deprecated exact dependency {dependency[0]}@{dependency[1]}")
            elif skill["state"] in {"reviewed", "validated"} and target["state"] == "draft":
                report.error(f"skill {skill['id']}: reviewed/validated skill depends on a draft")
            elif skill["state"] == "validated" and target["state"] != "validated":
                report.error(f"skill {skill['id']}: validated skill depends on an unvalidated skill")
        if focus in {"all", "skills"}:
            try:
                package = safe_path(root, skill["path"], exists=True)
                markdown = package / "SKILL.md"
                relative = markdown.relative_to(root).as_posix()
                content = safe_path(root, relative, exists=True).read_text(encoding="utf-8-sig")
                metadata, body = parse_frontmatter(content)
                if metadata["name"] != skill["id"]:
                    raise ProjectError("frontmatter name differs from registered ID")
                sections(body, SKILL_SECTIONS)
                check_prohibited(content, reviewed=skill["state"] in {"reviewed", "validated"})
                for directory, directories, files in os.walk(package, followlinks=False):
                    for name in directories + files:
                        path = Path(directory) / name
                        local = path.relative_to(root).as_posix()
                        safe_path(root, local, exists=True)
                        if not owns(agents[skill["owner"]], local):
                            raise ProjectError("skill owner lacks permitted ownership of a package asset")
                        if path.is_file() and path.suffix.lower() == ".md":
                            check_markdown_links(root, local, path.read_text(encoding="utf-8-sig"))
                cases = load_cases(root, skill)
                if skill["state"] == "validated":
                    evidence = [path for path in skill["evidence"] if path.endswith(".json")]
                    if not evidence:
                        raise ProjectError("validated state needs independent behavioral evidence JSON")
                    completed = set()
                    for path in evidence:
                        record = load_manual_evidence(root, path, skill, cases)
                        completed.update(identifier for identifier, entry in record["cases"].items() if entry["result"] == "passed")
                        if any(entry["result"] == "failed" for entry in record["cases"].values()):
                            raise ProjectError("validated state has failing manual evidence")
                    required = {case["id"] for case in cases if case["mode"] == "manual"}
                    if not required.issubset(completed):
                        raise ProjectError("validated state has missing/not_run manual behavioral cases")
                    for case in cases:
                        if case["mode"] == "executable" and not execute_assertion(root, case["assertion"])[0]:
                            raise ProjectError("validated state has a failing executable artifact assertion")
            except (ProjectError, OSError, UnicodeError, TypeError) as exc:
                report.error(f"skill {skill['id']} package: {exc}")

    visiting = set()
    visited = set()

    def visit(key: tuple[str, str]) -> None:
        if key in visiting:
            report.error("skill dependency cycle detected")
            return
        if key in visited:
            return
        visiting.add(key)
        for dependency in graph.get(key, []):
            visit(dependency)
        visiting.remove(key)
        visited.add(key)

    for key in graph:
        visit(key)
    report.counts = {"agents": len(agents), "skills": len(skills), "adapters": len(adapters)}
    return report


def print_report(report: Report, label: str) -> int:
    for message in report.errors:
        print(f"ERROR: {message}")
    for message in sorted(set(report.warnings)):
        print(f"WARNING: {message}")
    status = "passed" if report.ok else "failed"
    counts = ", ".join(f"{count} {name}" for name, count in report.counts.items())
    print(f"{label}: {status}" + (f" ({counts})" if counts else ""))
    if report.ok:
        print("Structural validation only; this does not prove skill behavior or enforce runtime permissions.")
    return 0 if report.ok else 1
