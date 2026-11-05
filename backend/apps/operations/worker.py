import uuid
from datetime import timedelta

from django.db import transaction
from django.db.models import Q
from django.utils import timezone

from apps.audit import service as audit
from apps.reports.crypto import digest, source_payload
from apps.reports.models import ReportVariant
from apps.reports.projection import POLICIES, PROFILE_RANK, project
from apps.reports.regeneration import job_is_current
from apps.scopes.models import Organization

from .models import ProcessingJob


LEASE_SECONDS = 120
MAX_ATTEMPTS = 3


def ready_jobs(now):
    return ProcessingJob.objects.filter(available_at__lte=now).filter(Q(status="PENDING") | Q(status="PROCESSING", lease_until__lte=now))


def claim_job():
    """Organization before job lock; transformation happens after this commit."""
    for job_id, org_id in ready_jobs(timezone.now()).order_by("available_at", "id").values_list("id", "organization_id")[:50]:
        with transaction.atomic():
            org = Organization.objects.select_for_update().get(pk=org_id)
            job = ready_jobs(timezone.now()).select_for_update(skip_locked=True).filter(pk=job_id).select_related("revision__report", "policy").first()
            if job is None:
                continue
            if not job_is_current(job, org):
                job.status, job.error_code = "FAILED", "STALE_CONTEXT"
                job.lease_token, job.lease_until = None, None
                job.save(update_fields=["status", "error_code", "lease_token", "lease_until"])
                audit.record(org_id, None, "PROCESSING_FAILED", job.id, error_code=job.error_code)
                continue
            if job.attempts >= MAX_ATTEMPTS:
                job.status, job.error_code = "FAILED", "ATTEMPTS_EXHAUSTED"
                job.lease_token, job.lease_until = None, None
                job.save(update_fields=["status", "error_code", "lease_token", "lease_until"])
                job.revision.processing_state = "FAILED"
                job.revision.save(update_fields=["processing_state"])
                audit.record(org_id, None, "PROCESSING_FAILED", job.id, error_code=job.error_code)
                continue
            job.attempts += 1
            job.lease_generation += 1
            job.lease_token = uuid.uuid4()
            job.lease_until = timezone.now() + timedelta(seconds=LEASE_SECONDS)
            job.status = "PROCESSING"
            job.error_code = None
            job.save(update_fields=["attempts", "lease_generation", "lease_token", "lease_until", "status", "error_code"])
            job.revision.processing_state = "PROCESSING"
            job.revision.save(update_fields=["processing_state"])
            return {"id": job.id, "organization_id": job.organization_id, "token": job.lease_token, "generation": job.lease_generation}
    return None


def projections_for(job):
    if (job.policy.version not in POLICIES or job.policy.rules != POLICIES[job.policy.version]
            or job.engine_manifest != job.policy.rules["engine"] or digest(job.policy.rules) != job.policy.rules_hash):
        raise ValueError("unsupported policy")
    payload = source_payload(job.revision)
    if job.scope_context is None:
        # The historical function result remains a single projection, not a wrapper.
        return project(payload, rules=job.policy.rules)
    if digest(job.scope_context) != job.scope_context_hash:
        raise ValueError("invalid frozen context")
    unit = job.revision.report.unit
    profiles = sorted({profile for channel in job.scope_context["channels"] for profile in channel["profiles"]},
                      key=lambda value: -PROFILE_RANK[value])
    return {profile: project(payload, profile,
        {"code": unit.code, "name": unit.name} if profile == "DEMO-FULL" else None, job.policy.rules) for profile in profiles}


def transform_job(lease):
    job = ProcessingJob.objects.select_related("revision__report__unit", "policy").get(pk=lease["id"])
    return projections_for(job)


def binding_for(variant):
    result = {"revision_id": str(variant.revision_id), "revision_no": variant.revision.revision_no,
            "candidate_hash": variant.candidate_hash, "policy_version": variant.policy.version,
            "policy_hash": variant.policy.rules_hash, "profile": variant.profile, "channel_ids": variant.channel_ids}
    if getattr(variant, "scope_context_hash", None) is not None:
        result["scope_context_hash"] = variant.scope_context_hash
    return result


def candidate_digest(projection, revision_id, revision_no, source_digest, policy_id, policy_hash, profile, channels,
                     *, scope_context_hash=None, policy_epoch=0, scope_epoch=0):
    value = {"projection": projection, "revision_id": str(revision_id), "revision_no": revision_no,
                   "source_digest": source_digest, "policy_id": str(policy_id), "policy_hash": policy_hash,
                   "profile": profile, "channel_ids": channels}
    if scope_context_hash is not None:
        value.update(scope_context_hash=scope_context_hash, policy_epoch=policy_epoch, scope_epoch=scope_epoch)
    return digest(value)


@transaction.atomic
def finish_job(lease, projection=None, error_code=None):
    org = Organization.objects.select_for_update().get(pk=lease["organization_id"])
    job = ProcessingJob.objects.select_for_update().select_related("revision__report__unit", "policy").get(pk=lease["id"])
    if job.status != "PROCESSING" or job.lease_token != lease["token"] or job.lease_generation != lease["generation"] or job.lease_until <= timezone.now():
        return False
    if not job_is_current(job, org):
        job.status, job.error_code = "FAILED", "STALE_CONTEXT"
        job.lease_token, job.lease_until = None, None
        job.save(update_fields=["status", "error_code", "lease_token", "lease_until"])
        audit.record(org.id, None, "PROCESSING_FAILED", job.id, error_code=job.error_code)
        # Never overwrite the replacement job's revision progress.
        return False
    if not error_code:
        try:
            if projection != projections_for(job):
                error_code = "RULE_PROCESSING_FAILED"
        except (ValueError, TypeError, KeyError, AttributeError):
            error_code = "RULE_PROCESSING_FAILED"
    if error_code:
        job.status, job.error_code = "FAILED", "RULE_PROCESSING_FAILED"
        job.revision.processing_state = "FAILED"
    else:
        projected = {"DEMO-REDUCED": projection} if job.scope_context is None else projection
        for profile, output in projected.items():
            channels = job.channel_ids if job.scope_context is None else [row["id"] for row in job.scope_context["channels"] if profile in row["profiles"]]
            candidate_hash = candidate_digest(output, job.revision_id, job.revision.revision_no, job.revision.content_digest,
                job.policy_id, job.policy.rules_hash, profile, channels, scope_context_hash=job.scope_context_hash,
                policy_epoch=job.policy_epoch, scope_epoch=job.scope_epoch)
            ReportVariant.objects.create(
                organization_id=job.organization_id, revision=job.revision, policy=job.policy, job=job,
                profile=profile, projection=output, candidate_hash=candidate_hash, channel_ids=channels,
                scope_context_hash=job.scope_context_hash,
                warnings=["Reporter, site and narrative remain private.", "The shared text uses only fixed sharing rules.", "Human review does not independently verify the reported event."],
            )
        job.status = "DONE"
        job.revision.processing_state = "AWAITING_REVIEW"
    job.lease_token, job.lease_until = None, None
    job.save(update_fields=["status", "error_code", "lease_token", "lease_until"])
    job.revision.save(update_fields=["processing_state"])
    audit.record(job.organization_id, None, "PROCESSING_FAILED" if error_code else "CANDIDATE_PREPARED", job.id,
                 lease_generation=job.lease_generation, **({"error_code": job.error_code} if error_code else {}))
    return True


def process_one():
    lease = claim_job()
    if lease is None:
        return False
    try:
        projection = transform_job(lease)
    except Exception:
        # Never log exception strings, source data or a traceback from the
        # transformation path. The failure is private and metadata-only.
        finish_job(lease, error_code="RULE_PROCESSING_FAILED")
    else:
        finish_job(lease, projection)
    return True
