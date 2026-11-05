"""Pure M3 scope-context canonicalization (TASK-120 contract, contracts/m3/scope-context.json). No Django imports."""
try:
    from .canonical import digest
    from .projection import PROFILE_RANK
except ImportError:  # standalone standard-library execution
    from apps.reports.canonical import digest
    from apps.reports.projection import PROFILE_RANK

DEFAULT_MAX = "DEMO-REDUCED"  # NULL max_profile counts as DEMO-REDUCED


def _rank(value):
    if value is None:
        return PROFILE_RANK[DEFAULT_MAX]
    if value not in PROFILE_RANK:
        raise ValueError("unsupported profile")
    return PROFILE_RANK[value]


def is_legacy(sources):
    """F01: exactly one active eligible source whose source and channel maxima are both NULL."""
    return len(sources) == 1 and sources[0]["source_max"] is None and sources[0]["channel_max"] is None


def build_context(unit_id, policy_epoch, scope_epoch, sources):
    """`sources`: active eligible sources as dicts {channel_id, channel_max, source_max}. Returns None for the legacy context."""
    if type(policy_epoch) is not int or type(scope_epoch) is not int or policy_epoch < 0 or scope_epoch < 0:
        raise ValueError("invalid epoch")
    ids = [source["channel_id"] for source in sources]
    if len(ids) != len(set(ids)) or not ids:
        raise ValueError("invalid sources")
    if is_legacy(sources):
        return None
    channels = []
    for source in sorted(sources, key=lambda item: str(item["channel_id"])):
        ceiling = min(_rank(source["channel_max"]), _rank(source["source_max"]))
        profiles = sorted((name for name, rank in PROFILE_RANK.items() if rank <= ceiling), key=lambda name: -PROFILE_RANK[name])
        channels.append({"id": str(source["channel_id"]), "profiles": profiles})
    return {"v": 1, "unit_id": str(unit_id), "policy_epoch": policy_epoch, "scope_epoch": scope_epoch, "channels": channels}


def context_hash(context):
    return None if context is None else digest(context)


def scope_epochs_digest(pairs):
    """FN2: digest of sorted [unit_id, scope_epoch] pairs for every unit sourcing a channel; bound into integration cursors."""
    values = sorted([str(unit_id), int(epoch)] for unit_id, epoch in pairs)
    return digest(values)
