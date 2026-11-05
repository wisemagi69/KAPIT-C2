"""Pure deterministic demonstration rules. No narrative-derived shared text."""
from datetime import datetime, timedelta, timezone


RULES = {
    "engine": "demo-rules-v1",
    "template": "demo-maintenance-v1",
    "profile": "DEMO-REDUCED",
    "categories": ["INFRASTRUCTURE", "WATER_SUPPLY", "EQUIPMENT"],
    "urgencies": ["ROUTINE", "PRIORITY"],
    "areas": ["Area A", "Area B", "Area C"],
    "assistance": ["Repair assistance", "Inspection", "Replacement parts"],
    "date_precision": "day_utc",
    "private_fields": ["site_label", "reporter_label", "narrative"],
}
PROJECTION_KEYS = {"title", "text", "category", "urgency", "area_label", "assistance_requested", "observed_date", "verification", "profile"}

# M3 (TASK-120 contract, contracts/m3/profiles.json and rules-v2.json). RULES_V1 is today's RULES, unchanged.
RULES_V1 = RULES
TEXT_TEMPLATES_V1 = {
    "DEMO-FULL": "{unit_name} reports {issue} in {area}; {assistance_lower} requested.",
    "DEMO-REDUCED": "A support unit reports {issue} in {area}; {assistance_lower} requested.",
    "DEMO-SUMMARY": "A support unit reports {issue}.",
}
RULES_V2 = {**RULES, "engine": "demo-rules-v2", "text_templates": {
    "DEMO-FULL": "{unit_name} requests maintenance support for {issue} in {area}; {assistance_lower}.",
    "DEMO-REDUCED": "Maintenance support is requested for {issue} in {area}; {assistance_lower}.",
    "DEMO-SUMMARY": "Maintenance support is requested for {issue}.",
}}
POLICIES = {"demo-policy-v1": RULES_V1, "demo-policy-v2": RULES_V2}
PROFILE_RANK = {"DEMO-SUMMARY": 1, "DEMO-REDUCED": 2, "DEMO-FULL": 3}
PROFILE_KEYS = {
    "DEMO-FULL": ("title", "text", "category", "urgency", "area_label", "assistance_requested", "observed_hour",
                  "originating_unit", "verification", "profile"),
    "DEMO-REDUCED": ("title", "text", "category", "urgency", "area_label", "assistance_requested", "observed_date",
                     "verification", "profile"),
    "DEMO-SUMMARY": ("title", "text", "category", "urgency", "observed_week", "verification", "profile"),
}
TITLES = {"INFRASTRUCTURE": "Infrastructure maintenance request", "WATER_SUPPLY": "Water supply maintenance request", "EQUIPMENT": "Equipment maintenance request"}
ISSUES = {"INFRASTRUCTURE": "an infrastructure maintenance issue", "WATER_SUPPLY": "a water supply issue", "EQUIPMENT": "an equipment maintenance issue"}


def text_templates(rules):
    if rules == RULES_V1:
        return TEXT_TEMPLATES_V1
    if rules == RULES_V2:
        return RULES_V2["text_templates"]
    raise ValueError("unsupported policy rules")


def _project_m1(payload):
    for key, allowed in [("category", RULES["categories"]), ("urgency", RULES["urgencies"]), ("area_label", RULES["areas"]), ("assistance_requested", RULES["assistance"])]:
        if payload.get(key) not in allowed:
            raise ValueError("unsupported projection input")
    observed = datetime.fromisoformat(payload["observed_at"].replace("Z", "+00:00"))
    if observed.tzinfo is None:
        raise ValueError("timezone required")
    titles = {"INFRASTRUCTURE": "Infrastructure maintenance request", "WATER_SUPPLY": "Water supply maintenance request", "EQUIPMENT": "Equipment maintenance request"}
    issue = {"INFRASTRUCTURE": "an infrastructure maintenance issue", "WATER_SUPPLY": "a water supply issue", "EQUIPMENT": "an equipment maintenance issue"}[payload["category"]]
    return {
        "title": titles[payload["category"]],
        "text": f"A support unit reports {issue} in {payload['area_label']}; {payload['assistance_requested'].lower()} requested.",
        "category": payload["category"], "urgency": payload["urgency"],
        "area_label": payload["area_label"], "assistance_requested": payload["assistance_requested"],
        "observed_date": observed.astimezone(timezone.utc).date().isoformat(),
        "verification": "Human reviewed", "profile": "DEMO-REDUCED",
    }


def _unit_snapshot(unit):
    if (not isinstance(unit, dict) or set(unit) != {"code", "name"}
            or not all(isinstance(unit[key], str) and 0 < len(unit[key]) <= 80 for key in unit)):
        raise ValueError("originating unit snapshot required")
    return {"code": unit["code"], "name": unit["name"]}


def project(payload, profile="DEMO-REDUCED", unit=None, rules=RULES_V1):
    """Allowlisted fields only; the defaults reproduce M1 byte-for-byte (TASK-120 QN4)."""
    if profile == "DEMO-REDUCED" and unit is None and rules == RULES_V1:
        return _project_m1(payload)
    if profile not in PROFILE_KEYS:
        raise ValueError("unsupported profile")
    templates = text_templates(rules)
    checks = [("category", rules["categories"]), ("urgency", rules["urgencies"])]
    if profile != "DEMO-SUMMARY":
        checks += [("area_label", rules["areas"]), ("assistance_requested", rules["assistance"])]
    for key, allowed in checks:
        if payload.get(key) not in allowed:
            raise ValueError("unsupported projection input")
    observed = datetime.fromisoformat(payload["observed_at"].replace("Z", "+00:00"))
    if observed.tzinfo is None:
        raise ValueError("timezone required")
    observed = observed.astimezone(timezone.utc)
    snapshot = _unit_snapshot(unit) if profile == "DEMO-FULL" else None
    if profile != "DEMO-FULL" and unit is not None:
        raise ValueError("unit snapshot is only part of DEMO-FULL")
    values = {"unit_name": snapshot["name"] if snapshot else "", "issue": ISSUES[payload["category"]]}
    if profile != "DEMO-SUMMARY":
        values.update(area=payload["area_label"], assistance_lower=payload["assistance_requested"].lower())
    week = observed.isocalendar()
    full = {"title": TITLES[payload["category"]], "text": templates[profile].format(**values),
            "category": payload["category"], "urgency": payload["urgency"],
            "area_label": payload["area_label"] if profile != "DEMO-SUMMARY" else None,
            "assistance_requested": payload["assistance_requested"] if profile != "DEMO-SUMMARY" else None,
            "observed_hour": observed.strftime("%Y-%m-%dT%H:00:00Z"), "observed_date": observed.date().isoformat(),
            "observed_week": f"{week[0]}-W{week[1]:02d}", "originating_unit": snapshot,
            "verification": "Human reviewed", "profile": profile}
    return {key: full[key] for key in PROFILE_KEYS[profile]}


def _observed_from(projection, profile):
    if profile == "DEMO-FULL":
        return projection["observed_hour"]
    if profile == "DEMO-REDUCED":
        return projection["observed_date"] + "T00:00:00Z"
    year, week = projection["observed_week"].split("-W")
    monday = datetime.fromisocalendar(int(year), int(week), 1)
    return monday.strftime("%Y-%m-%dT00:00:00Z")


def valid_projection(projection, profile="DEMO-REDUCED", unit=None, rules=RULES_V1):
    if profile not in PROFILE_KEYS:
        return False
    if profile == "DEMO-REDUCED" and unit is None and rules == RULES_V1:
        if not isinstance(projection, dict) or set(projection) != PROJECTION_KEYS:
            return False
        try:
            # Reconstruct only from the safe enum/day fields, never private content.
            expected = project({**projection, "observed_at": projection["observed_date"] + "T00:00:00Z"})
        except (KeyError, ValueError, TypeError, AttributeError):
            return False
        return expected == projection
    if not isinstance(projection, dict) or set(projection) != set(PROFILE_KEYS[profile]) or projection.get("profile") != profile:
        return False
    try:
        # FULL compares the snapshot with the unit's current values; a mismatch fails closed.
        if profile == "DEMO-FULL" and _unit_snapshot(unit) != projection["originating_unit"]:
            return False
        source = {key: projection[key] for key in ("category", "urgency", "area_label", "assistance_requested") if key in projection}
        expected = project({**source, "observed_at": _observed_from(projection, profile)}, profile, unit, rules)
    except (KeyError, ValueError, TypeError, AttributeError):
        return False
    return expected == projection


def served_published_at(published_at, profile):
    """S4: the served publication time, truncated to the profile's precision (ordering uses the stored value)."""
    value = published_at.astimezone(timezone.utc)
    if profile == "DEMO-FULL":
        value = value.replace(minute=0, second=0, microsecond=0)
    elif profile == "DEMO-REDUCED":
        value = value.replace(hour=0, minute=0, second=0, microsecond=0)
    elif profile == "DEMO-SUMMARY":
        value = (value - timedelta(days=value.weekday())).replace(hour=0, minute=0, second=0, microsecond=0)
    else:
        raise ValueError("unsupported profile")
    return value.isoformat()
