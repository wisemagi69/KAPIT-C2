import uuid

from django.db import transaction

from apps.audit import service as audit
from apps.operations.errors import ApiError, missing
from apps.operations.worker import binding_for, candidate_digest, projections_for
from apps.publications.models import Publication, RevisionWithdrawal
from apps.publications.services import remove_report_publications
from apps.reports.crypto import decrypt, digest, encrypt, source_payload
from apps.reports.models import ReportVariant, ReportRevision
from apps.reports.projection import PROFILE_RANK
from apps.reports.regeneration import job_is_current, latest_job
from apps.reports.selectors import source_report
from apps.reports.services import current_policy
from apps.scopes.access import PROFILE, eligible_channels, lock_identity, require_role

from .models import DecisionBatch, ReviewDecision


def review_variant(actor, variant_id, lock=False):
    queryset = ReportVariant.objects.filter(pk=variant_id, organization_id=actor.organization_id).select_related("revision__report", "policy")
    if lock:
        queryset = queryset.select_for_update(of=("self",))
    variant = queryset.first()
    if variant is None:
        raise missing()
    source_report(actor, variant.revision.report_id, reviewer_only=True, lock=lock)
    return variant


def verified_candidate(variant, org):
    if variant.scope_context_hash is not None:
        raise ApiError("USE_CANDIDATE_SET", "Review the complete candidate set for this source.", 409)
    revision = variant.revision
    policy = current_policy(org)
    channels = sorted(str(value) for value in eligible_channels(org.id, revision.report.unit_id))
    if not job_is_current(variant.job, org) or variant.policy_id != policy.id or revision.revision_no != revision.report.current_revision_no or variant.profile != PROFILE or variant.channel_ids != channels or len(channels) != 1:
        raise ApiError("STALE_REVIEW", "This candidate is no longer current. Reload before deciding.", 409)
    payload = source_payload(revision)
    calculated = candidate_digest(variant.projection, revision.id, revision.revision_no, revision.content_digest,
                                  variant.policy_id, policy.rules_hash, variant.profile, variant.channel_ids)
    if variant.candidate_hash != calculated or variant.projection != projections_for(variant.job):
        raise ApiError("STALE_REVIEW", "This candidate is no longer current. Reload before deciding.", 409)
    return payload


def normalized_binding(data):
    return {"revision_id": str(data["revision_id"]), "revision_no": data["revision_no"], "candidate_hash": data["candidate_hash"],
            "policy_version": data["policy_version"], "policy_hash": data["policy_hash"], "profile": data["profile"],
            "channel_ids": [str(value) for value in data["channel_ids"]]}


@transaction.atomic
def decide(user, variant_id, data, raw_body):
    actor, org = lock_identity(user)
    require_role(actor, "reviewer")
    # Report before candidate lock, as required by the reviewed lock protocol.
    preliminary = ReportVariant.objects.filter(pk=variant_id, organization_id=org.id).values_list("revision__report_id", flat=True).first()
    if preliminary is None:
        raise missing()
    report = source_report(actor, preliminary, reviewer_only=True, lock=True)
    variant = review_variant(actor, variant_id, lock=True)
    if report.author_id == actor.id or variant.revision.submitted_by_id == actor.id:
        raise ApiError("SELF_APPROVAL_DENIED", "The submitting author cannot decide on this source.", 403)
    request_hash = digest({"route": f"POST /variants/{variant_id}/decisions/", "body": raw_body})
    previous = ReviewDecision.objects.filter(reviewer=actor, operation_id=data["operation_id"]).first()
    if previous:
        if previous.request_hash != request_hash or previous.variant_id != variant.id:
            raise ApiError("IDEMPOTENCY_CONFLICT", "This decision operation has already been recorded with a different request.", 409)
        # Replay returns the historical decision only under current authority.
        # It never reactivates a publication or creates any new side effect.
        return previous.response_body
    if data["action"] == "APPROVE" and RevisionWithdrawal.objects.filter(revision=variant.revision).exists():
        raise ApiError("WITHDRAWAL_CONFLICT", "This source revision was withdrawn.", 409)
    if variant.scope_context_hash is not None:
        raise ApiError("USE_CANDIDATE_SET", "Review the complete candidate set for this source.", 409)
    if variant.state != "CANDIDATE" or ReviewDecision.objects.filter(variant=variant).exists():
        raise ApiError("DECISION_CONFLICT", "This candidate already has a decision. Reload its current status.", 409)
    verified_candidate(variant, org)
    binding = binding_for(variant)
    if normalized_binding(data["expected"]) != binding:
        raise ApiError("STALE_REVIEW", "The reviewed content or audience changed. Reload before deciding.", 409)
    action = data["action"]
    status = {"APPROVE": "APPROVED", "RETURN": "RETURNED", "REJECT": "REJECTED"}[action]
    decision_id = uuid.uuid4()
    publication_ids = [uuid.uuid4() for _ in variant.channel_ids] if action == "APPROVE" else []
    result = {"decision_id": str(decision_id), "action": action,
              "publication_ids": [str(value) for value in publication_ids], "report_status": status}
    variant.state = status
    variant.save(update_fields=["state"])
    decision = ReviewDecision.objects.create(
        id=decision_id, organization=org, variant=variant, reviewer=actor, operation_id=data["operation_id"],
        request_hash=request_hash, action=action, binding=binding,
        reason_ciphertext=encrypt(data["reason"]) if data["reason"] else None, response_body=result,
    )
    if action == "APPROVE":
        remove_report_publications(org, report, cause="REAPPROVAL", actor=actor,
            tuples={(str(channel), variant.profile) for channel in variant.channel_ids})
        for pub_id, channel_id in zip(publication_ids, variant.channel_ids, strict=True):
            Publication.objects.create(id=pub_id, organization=org, variant=variant, decision=decision,
                                       channel_id=channel_id, report=report, profile=variant.profile, projection=variant.projection)
    audit.record(org.id, actor, "REVIEW_DECISION", variant.id, action=action, operation_id=str(data["operation_id"]))
    return result


def _locked_revision(user, revision_id):
    actor, org = lock_identity(user)
    require_role(actor, "reviewer")
    link = ReportRevision.objects.filter(pk=revision_id, organization=org).values_list("report_id", flat=True).first()
    if link is None:
        raise missing()
    report = source_report(actor, link, reviewer_only=True, lock=True)
    revision = ReportRevision.objects.select_for_update().get(pk=revision_id, report=report, organization=org)
    if report.author_id == actor.id or revision.submitted_by_id == actor.id:
        raise ApiError("SELF_APPROVAL_DENIED", "The submitting author cannot review this source.", 403)
    return actor, org, report, revision


def _stale():
    return ApiError("STALE_REVIEW", "The complete content or audience changed. Reload before deciding.", 409)


def _complete_set(revision, org):
    job = latest_job(revision)
    if job is None or job.status != "DONE" or not job_is_current(job, org):
        raise _stale()
    variants = list(job.variants.select_for_update(of=("self",)).select_related("revision__report", "policy", "job__revision__report__unit", "job__policy").order_by("id"))
    try:
        projected = projections_for(job)
        expected = {PROFILE: projected} if job.scope_context is None else projected
        if len(variants) != len(expected) or {row.profile for row in variants} != set(expected):
            raise _stale()
        for variant in variants:
            channels = job.channel_ids if job.scope_context is None else [entry["id"] for entry in job.scope_context["channels"] if variant.profile in entry["profiles"]]
            computed = candidate_digest(expected[variant.profile], revision.id, revision.revision_no, revision.content_digest,
                job.policy_id, job.policy.rules_hash, variant.profile, channels,
                scope_context_hash=job.scope_context_hash, policy_epoch=job.policy_epoch, scope_epoch=job.scope_epoch)
            if (variant.revision_id != revision.id or variant.organization_id != org.id or variant.policy_id != job.policy_id
                    or variant.scope_context_hash != job.scope_context_hash or variant.channel_ids != channels
                    or variant.projection != expected[variant.profile] or variant.candidate_hash != computed):
                raise _stale()
    except (ValueError, TypeError, KeyError, AttributeError):
        raise _stale() from None
    ordered = sorted(variants, key=lambda value: (-PROFILE_RANK[value.profile], str(value.id)))
    binding = {"revision_id": str(revision.id), "revision_no": revision.revision_no,
        "policy_version": job.policy.version, "policy_hash": job.policy.rules_hash,
        "scope_context_hash": job.scope_context_hash, "candidates": [
            {"variant_id": str(value.id), "profile": value.profile, "candidate_hash": value.candidate_hash,
             "channel_ids": value.channel_ids} for value in ordered]}
    return ordered, binding


def normalized_set_binding(data):
    return {"revision_id": str(data["revision_id"]), "revision_no": data["revision_no"],
        "policy_version": data["policy_version"], "policy_hash": data["policy_hash"],
        "scope_context_hash": data["scope_context_hash"], "candidates": [
            {"variant_id": str(row["variant_id"]), "profile": row["profile"], "candidate_hash": row["candidate_hash"],
             "channel_ids": [str(channel) for channel in row["channel_ids"]]} for row in data["candidates"]]}


@transaction.atomic
def candidate_set(user, revision_id):
    actor, org, report, revision = _locked_revision(user, revision_id)
    if RevisionWithdrawal.objects.filter(revision=revision).exists():
        raise ApiError("WITHDRAWAL_CONFLICT", "This source revision was withdrawn.", 409)
    variants, binding = _complete_set(revision, org)
    from apps.reports.selectors import summary
    result = {"report": summary(report, revision), "source": source_payload(revision), "binding": binding,
        "candidates": [{"variant_id": str(value.id), "profile": value.profile, "candidate": value.projection,
                        "warnings": value.warnings, "state": value.state} for value in variants]}
    if revision.correction_reason_ciphertext is not None:
        result["correction_reason"] = decrypt(revision.correction_reason_ciphertext)
    audit.record(org.id, actor, "REVIEW_READ", revision.id)
    return result


@transaction.atomic
def decide_batch(user, revision_id, data, raw_body):
    actor, org, report, revision = _locked_revision(user, revision_id)
    request_hash = digest({"route": f"POST /revisions/{revision_id}/decisions/", "body": raw_body})
    previous = DecisionBatch.objects.filter(reviewer=actor, operation_id=data["operation_id"]).first()
    if previous:
        if previous.revision_id != revision.id or previous.request_hash != request_hash:
            raise ApiError("IDEMPOTENCY_CONFLICT", "This batch operation has a different request.", 409)
        return previous.response_body
    if RevisionWithdrawal.objects.filter(revision=revision).exists():
        raise ApiError("WITHDRAWAL_CONFLICT", "This source revision was withdrawn.", 409)
    variants, binding = _complete_set(revision, org)
    if any(value.state != "CANDIDATE" or ReviewDecision.objects.filter(variant=value).exists() for value in variants):
        raise ApiError("DECISION_CONFLICT", "This candidate set already has a decision.", 409)
    if normalized_set_binding(data["expected"]) != binding:
        raise _stale()
    action, selected = data["action"], set(data["approve_profiles"])
    if (action not in {"APPROVE", "RETURN", "REJECT"} or len(selected) != len(data["approve_profiles"])
            or not selected <= {value.profile for value in variants}
            or (action == "APPROVE" and not selected) or (action != "APPROVE" and selected)
            or (action != "APPROVE" and not (data["reason"] or "").strip())):
        raise ApiError("INVALID_REQUEST", "Choose a valid complete-set decision.")
    planned = [(value, action if action != "APPROVE" or value.profile in selected else None) for value in variants]
    operation_id = uuid.UUID(str(data["operation_id"]))
    if ReviewDecision.objects.filter(reviewer=actor, operation_id__in=[uuid.uuid5(operation_id, str(value.id)) for value, child_action in planned if child_action]).exists():
        raise ApiError("IDEMPOTENCY_CONFLICT", "This batch operation conflicts with a recorded decision.", 409)
    batch_id = uuid.uuid4()
    publication_plan = [(value, channel, uuid.uuid4()) for value in variants if action == "APPROVE" and value.profile in selected for channel in value.channel_ids]
    result = {"batch_id": str(batch_id), "action": action, "report_status": {"APPROVE": "APPROVED", "RETURN": "RETURNED", "REJECT": "REJECTED"}[action],
        "publication_ids": [str(pub_id) for _, _, pub_id in publication_plan],
        "approved_profiles": [value.profile for value in variants if value.profile in selected],
        "withheld_profiles": [value.profile for value, child_action in planned if child_action is None],
        "withheld_variant_ids": [str(value.id) for value, child_action in planned if child_action is None]}
    reason = encrypt(data["reason"]) if data["reason"] else None
    batch = DecisionBatch.objects.create(id=batch_id, organization=org, reviewer=actor, revision=revision,
        operation_id=operation_id, request_hash=request_hash, action=action, binding=binding,
        reason_ciphertext=reason, response_body=result)
    decisions = {}
    for variant, child_action in sorted(planned, key=lambda pair: str(pair[0].id)):
        variant.state = {"APPROVE": "APPROVED", "RETURN": "RETURNED", "REJECT": "REJECTED", None: "REJECTED"}[child_action]
        variant.save(update_fields=["state"])
        if child_action is not None:
            decisions[variant.id] = ReviewDecision.objects.create(organization=org, variant=variant, reviewer=actor,
                operation_id=uuid.uuid5(operation_id, str(variant.id)), request_hash=request_hash, action=child_action,
                binding=binding_for(variant), reason_ciphertext=reason, batch=batch, response_body={"batch_id": str(batch_id), "action": child_action})
    if publication_plan:
        remove_report_publications(org, report, cause="REAPPROVAL", actor=actor,
            tuples={(str(channel), value.profile) for value, channel, _ in publication_plan})
        for variant, channel, pub_id in publication_plan:
            Publication.objects.create(id=pub_id, organization=org, report=report, variant=variant,
                decision=decisions[variant.id], channel_id=channel, profile=variant.profile, projection=variant.projection)
    audit.record(org.id, actor, "REVIEW_BATCH", revision.id, action=action, operation_id=str(operation_id))
    return result
