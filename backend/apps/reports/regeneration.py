"""Current-context processing and irreversible invalidation, under the organization lock."""
from contextlib import contextmanager
from contextvars import ContextVar

from django.db import IntegrityError, transaction
from django.utils import timezone

from apps.audit import service as audit
from apps.operations.errors import ApiError
from apps.operations.models import ProcessingJob
from apps.publications.models import Publication, PublicationRemoval, RevisionWithdrawal
from apps.scopes.models import ChannelSource, Organization, Unit

from .models import ReportRevision
from .scope_context import build_context, context_hash


def processing_scope(org, unit):
    if not org.active or not unit.active or unit.organization_id != org.id:
        raise ApiError("SCOPE_UNAVAILABLE", "The sharing context is unavailable.", 409)
    sources = list(ChannelSource.objects.filter(organization=org, unit=unit, active=True,
        channel__organization=org, channel__active=True).select_related("channel").order_by("channel_id"))
    if not sources:
        raise ApiError("SCOPE_UNAVAILABLE", "The sharing context is unavailable.", 409)
    context = build_context(unit.id, org.policy_epoch, unit.scope_epoch,
        [{"channel_id": str(row.channel_id), "channel_max": row.channel.max_profile, "source_max": row.max_profile} for row in sources])
    return context, [str(row.channel_id) for row in sources]


_scope_memo = ContextVar("kapit_scope_memo", default=None)


@contextmanager
def scope_memo():
    """Reuse organization, unit, policy and channel-scope lookups for one read.

    Only for a caller that already holds the organization lock (lock_identity):
    policy and scope changes take the same lock, so these values cannot change
    while the memo is active. Per-revision checks are never memoized.
    """
    token = _scope_memo.set({})
    try:
        yield
    finally:
        _scope_memo.reset(token)


def _memoized(key, compute):
    memo = _scope_memo.get()
    if memo is None:
        return compute()
    if key not in memo:
        memo[key] = compute()
    return memo[key]


def _live_scope(org, unit):
    from .services import current_policy
    try:
        policy = current_policy(org)
        context, channels = processing_scope(org, unit)
    except ApiError:
        return None
    return policy, context, channels


def latest_job(revision):
    return revision.jobs.order_by("-policy_epoch", "-scope_epoch", "-available_at", "-id").first()


def current_job(revision):
    """A current private queue excludes stale work; terminal decisions remain historical."""
    job = latest_job(revision)
    if job is None or revision.revision_no != revision.report.current_revision_no:
        return job
    org = _memoized(("org", revision.organization_id), lambda: Organization.objects.get(pk=revision.organization_id))
    if job_is_current(job, org):
        return job
    states = list(job.variants.values_list("state", flat=True))
    # Whole-set RETURN/REJECT is a terminal private decision, preserved across epochs.
    if states and not any(state in {"CANDIDATE", "APPROVED"} for state in states):
        return job
    return None


def latest_variants(revision):
    job = latest_job(revision)
    return list(job.variants.select_related("job", "policy", "decision").order_by("profile", "id")) if job else []


def representative_variant(revision, job=None):
    """Pass a job already returned by current_job for this revision to avoid recomputing it."""
    priority = {"APPROVED": 0, "CANDIDATE": 1, "RETURNED": 2, "REJECTED": 3}
    job = current_job(revision) if job is None else job
    variants = list(job.variants.select_related("job", "policy", "decision")) if job else []
    return min(variants, key=lambda value: (priority[value.state], value.profile, value.id)) if variants else None


def job_is_current(job, org):
    """Both epochs and exact live context are required, including for legacy jobs."""
    revision = job.revision
    report = revision.report
    unit = _memoized(("unit", org.id, report.unit_id), lambda: Unit.objects.get(pk=report.unit_id, organization=org))
    scope = _memoized(("scope", org.id, unit.id), lambda: _live_scope(org, unit))
    if scope is None:
        return False
    policy, context, channels = scope
    return (job.organization_id == org.id and report.organization_id == org.id
            and revision.organization_id == org.id and revision.revision_no == report.current_revision_no
            and job.policy_id == policy.id and job.engine_manifest == policy.rules["engine"]
            and job.policy_epoch == org.policy_epoch and job.scope_epoch == unit.scope_epoch
            and job.scope_context == context and job.scope_context_hash == context_hash(context)
            and job.channel_ids == channels
            and not RevisionWithdrawal.objects.filter(organization=org, revision=revision).exists())


def queue_job(org, unit, revision, *, policy=None):
    """Caller holds the organization lock; unique replay is a savepoint-local no-op."""
    from .services import current_policy
    active = current_policy(org)
    if policy is not None and (policy.id != active.id or policy.organization_id != org.id):
        raise ApiError("POLICY_UNAVAILABLE", "The sharing policy is unavailable. Sharing remains private.", 409)
    policy = active
    context, channels = processing_scope(org, unit)
    identity = dict(revision=revision, policy=policy, engine_manifest=policy.rules["engine"],
                    policy_epoch=org.policy_epoch, scope_epoch=unit.scope_epoch,
                    scope_context_hash=context_hash(context))
    existing = ProcessingJob.objects.filter(**identity).first()
    if existing:
        return existing, False
    try:
        with transaction.atomic():
            job = ProcessingJob.objects.create(organization=org, scope_context=context, channel_ids=channels,
                                               available_at=timezone.now(), **identity)
    except IntegrityError:
        # Only map a conflict when the exact durable identity now exists.
        job = ProcessingJob.objects.filter(**identity).first()
        if job is None:
            raise
        return job, False
    revision.processing_state = "PENDING"
    revision.save(update_fields=["processing_state"])
    audit.record(org.id, None, "REGENERATION_QUEUED", job.id)
    return job, True


def remove_publications(org, unit_ids, *, cause, actor=None):
    if cause not in {"POLICY", "SCOPE", "CORRECTION", "REAPPROVAL", "WITHDRAWAL"}:
        raise ValueError("unsupported removal cause")
    now = timezone.now()
    publications = Publication.objects.select_for_update().filter(organization=org,
        report__unit_id__in=unit_ids, revoked_at__isnull=True).order_by("id")
    for publication in publications:
        PublicationRemoval.objects.get_or_create(publication=publication, defaults={"organization": org,
            "kind": "WITHDRAWN" if cause == "WITHDRAWAL" else "SUPERSEDED", "cause": cause,
            "actor": actor, "removed_at": now})
        publication.revoked_at = now
        publication.save(update_fields=["revoked_at"])


def regenerate_units(org, unit_ids):
    """Queue only latest undecided/approved current revisions; never revive a withdrawal."""
    from .services import current_policy
    try:
        policy = current_policy(org)
    except ApiError:
        return []
    result = []
    revisions = ReportRevision.objects.filter(organization=org, report__unit_id__in=unit_ids,
        report__unit__active=True).select_related("report", "report__unit").order_by("report_id", "revision_no")
    for revision in revisions:
        if revision.revision_no != revision.report.current_revision_no:
            continue
        if RevisionWithdrawal.objects.filter(organization=org, revision=revision).exists():
            continue
        variants = latest_variants(revision)
        if variants and not any(variant.state in {"CANDIDATE", "APPROVED"} for variant in variants):
            continue
        if not variants and revision.processing_state not in {"PENDING", "PROCESSING"}:
            continue
        try:
            processing_scope(org, revision.report.unit)
        except ApiError:
            continue
        job, created = queue_job(org, revision.report.unit, revision, policy=policy)
        if created:
            result.append(job)
    return result


@transaction.atomic
def invalidate_policy(org, *, actor=None):
    """Policy service calls after pointer/flag change, in its same transaction.

    This helper does not grant policy authority or change a policy pointer. Caller
    remains responsible for the reviewed two-person activation protocol.
    """
    locked = Organization.objects.select_for_update().get(pk=org.pk)
    locked.policy_epoch += 1
    locked.save(update_fields=["policy_epoch"])
    units = list(Unit.objects.filter(organization=locked).order_by("id").values_list("id", flat=True))
    remove_publications(locked, units, cause="POLICY", actor=actor)
    result = regenerate_units(locked, units)
    audit.record(locked.id, actor, "POLICY_APPLIED", locked.id)
    org.policy_epoch = locked.policy_epoch
    return result


def invalidate_scope(org, unit_ids, *, actor=None):
    """Topology caller already holds organization/identity locks and owns this transaction."""
    units = list(Unit.objects.select_for_update().filter(organization=org, id__in=unit_ids).order_by("id"))
    for unit in units:
        unit.scope_epoch += 1
        unit.save(update_fields=["scope_epoch"])
    ids = [unit.id for unit in units]
    remove_publications(org, ids, cause="SCOPE", actor=actor)
    result = regenerate_units(org, ids)
    audit.record(org.id, actor, "SCOPE_CHANGED", org.id)
    return result
