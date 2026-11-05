from django.db import IntegrityError, transaction
from django.utils import timezone
from django.utils.dateparse import parse_datetime

from apps.audit import service as audit
from apps.operations.errors import ApiError, missing
from apps.operations.models import ProcessingJob, SyncReceipt
from apps.scopes.access import eligible_channels, lock_identity, source_allowed, submitter_unit

from .crypto import digest, encrypt
from .models import Report, ReportRevision
from .projection import POLICIES


def current_policy(org):
    policy = org.active_policy
    if (policy is None or not org.active or not policy.active or policy.organization_id != org.id
            or policy.version not in POLICIES or policy.rules != POLICIES[policy.version]
            or digest(policy.rules) != policy.rules_hash):
        raise ApiError("POLICY_UNAVAILABLE", "The sharing policy is unavailable. Sharing remains private.", 409)
    return policy


def receipt_body(revision):
    return {"operation_id": str(revision.operation_id), "report_id": str(revision.report_id), "revision_id": str(revision.id), "revision_no": revision.revision_no,
            "delivery_status": "RECEIVED", "processing_status": "PENDING", "shared": False}


def correction_permissions(revision):
    """Return (mobile_returned, web_allowed) from one current-set interpretation.

    Prior approval permits correction while an actual replacement is pending or
    still CANDIDATE. It never overrides a newer terminal rejection/failure.
    Withdrawal of the approved revision still permits a fresh N+1 and review.
    """
    from .regeneration import latest_job
    job = latest_job(revision)
    if job is None or job.status == "FAILED":
        return False, False
    rows = list(job.variants.values_list("state", "decision__action", "decision__organization_id"))
    states = [state for state, _, _ in rows]
    returned = job.status == "DONE" and bool(rows) and all(
        state == "RETURNED" and action == "RETURN" and organization_id == revision.organization_id
        for state, action, organization_id in rows)
    approved = job.status == "DONE" and any(
        state == "APPROVED" and action == "APPROVE" and organization_id == revision.organization_id
        for state, action, organization_id in rows)
    if returned or approved:
        return returned, True
    replacing = job.status in {"PENDING", "PROCESSING"} or (job.status == "DONE" and bool(states) and all(state == "CANDIDATE" for state in states))
    historical_approval = replacing and revision.variants.exclude(job_id=job.id).filter(
        state="APPROVED", decision__action="APPROVE", decision__organization_id=revision.organization_id).exists()
    return False, bool(historical_approval)


def web_can_correct(actor, report, revision):
    if (actor.role != "submitter" or report.author_id != actor.id or revision.revision_no != report.current_revision_no
            or not source_allowed(actor, report)):
        return False
    return correction_permissions(revision)[1]


@transaction.atomic
def accept_operation(user, data, raw_body):
    actor, org = lock_identity(user)
    return _accept_locked(actor, org, None, data, raw_body)


def _accept_locked(actor, org, accepted_device, data, raw_body):
    """Internal core: web/mobile wrappers own authority locks through commit.

    Origin is supplied only by the authenticated wrapper, never by wire input.
    A NULL origin preserves the historical browser acceptance namespace.
    """
    unit = submitter_unit(actor)
    request_hash = digest({"route": "POST /sync/operations/", "body": raw_body})
    receipt = SyncReceipt.objects.filter(accepted_user=actor, organization=org,
        accepted_device=accepted_device, operation_id=data["operation_id"]).select_related("revision__report").first()
    if receipt is not None:
        if receipt.request_hash != request_hash:
            raise ApiError("IDEMPOTENCY_CONFLICT", "This operation was already accepted with a different request.", 409)
        if not source_allowed(actor, receipt.revision.report):
            raise missing()
        return receipt.response_body, False
    # The permanent revision acceptance identity protects replay even if a future
    # approved retention policy removes the receipt body.
    accepted = ReportRevision.objects.filter(submitted_by=actor, organization=org,
        accepted_device=accepted_device, operation_id=data["operation_id"]).select_related("report").first()
    if accepted is not None:
        if accepted.request_hash != request_hash:
            raise ApiError("IDEMPOTENCY_CONFLICT", "This operation was already accepted with a different request.", 409)
        if not source_allowed(actor, accepted.report):
            raise missing()
        return receipt_body(accepted), False
    expected_revision = data["expected_revision"]
    if expected_revision == 0:
        if Report.objects.filter(pk=data["report_id"]).exists():
            raise ApiError("REVISION_CONFLICT", "This report identifier cannot accept an initial revision.", 409)
        report = None
        revision_no = 1
    else:
        # The organization/identity locks above serialize corrections with every
        # review and access change; the report lock guards its revision pointer.
        report = Report.objects.select_for_update().filter(pk=data["report_id"], organization=org).first()
        if report is None and not Report.objects.filter(pk=data["report_id"]).exists():
            # Contract: a nonzero expected revision for an unused identifier is a conflict;
            # identifier existence is already disclosed by the initial-revision branch.
            raise ApiError("REVISION_CONFLICT", "This report identifier has no revision to correct.", 409)
        if report is None or report.author_id != actor.id or report.unit_id != unit.id or not source_allowed(actor, report):
            raise missing()
        if report.current_revision_no != expected_revision:
            raise ApiError("REVISION_CONFLICT", "This report has a newer revision. Reload its history.", 409)
        current = report.revisions.get(revision_no=expected_revision)
        returned, web_allowed = correction_permissions(current)
        # Device origin is authenticated, never a client-provided web flag.
        if not returned and not (accepted_device is None and web_allowed):
            raise ApiError("CORRECTION_UNAVAILABLE", "This source revision cannot currently accept a correction.", 409)
        if accepted_device is None and (not isinstance(data.get("correction_reason"), str)
                or not data["correction_reason"].strip() or len(data["correction_reason"]) > 500):
            raise ApiError("CORRECTION_UNAVAILABLE", "A private correction reason is required.", 409)
        revision_no = expected_revision + 1
    policy = current_policy(org)
    from .regeneration import processing_scope, queue_job
    # Freeze eligibility/epochs under the same organization lock as acceptance.
    processing_scope(org, unit)
    payload = data["payload"]
    if report is None:
        try:
            # A global report UUID can race across separately locked orgs.
            # Roll back this savepoint before mapping only the known conflict.
            with transaction.atomic():
                report = Report.objects.create(id=data["report_id"], organization=org, unit=unit, author=actor)
        except IntegrityError as exc:
            if getattr(getattr(exc.__cause__, "diag", None), "constraint_name", None) != "reports_report_pkey":
                raise
            raise ApiError("REVISION_CONFLICT", "This report identifier cannot accept an initial revision.", 409) from None
    else:
        from apps.publications.services import remove_report_publications
        remove_report_publications(org, report, cause="CORRECTION", actor=actor)
        report.current_revision_no = revision_no
        report.save(update_fields=["current_revision_no"])
    revision = ReportRevision.objects.create(
        organization=org, report=report, revision_no=revision_no, submitted_by=actor, template_version=data["template_version"],
        observed_at=parse_datetime(payload["observed_at"]), payload_ciphertext=encrypt(payload), content_digest=digest(payload),
        operation_id=data["operation_id"], request_hash=request_hash, accepted_device=accepted_device,
        correction_reason_ciphertext=encrypt(data["correction_reason"]) if expected_revision > 0 and accepted_device is None else None,
    )
    queue_job(org, unit, revision, policy=policy)
    result = receipt_body(revision)
    SyncReceipt.objects.create(organization=org, accepted_user=actor, accepted_device=accepted_device,
        operation_id=data["operation_id"], request_hash=request_hash, revision=revision, response_body=result)
    audit.record(org.id, actor, "SOURCE_ACCEPTED", report.id, operation_id=str(data["operation_id"]), revision_no=revision_no)
    if expected_revision > 0:
        audit.record(org.id, actor, "CORRECTION_SUPERSEDED", report.id, operation_id=str(data["operation_id"]), revision_no=revision_no)
    return result, True
