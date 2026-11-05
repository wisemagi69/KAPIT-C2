"""Report-scoped permanent removals and durable reviewer withdrawal."""
import uuid

from django.db import transaction
from django.utils import timezone

from apps.audit import service as audit
from apps.operations.errors import ApiError
from apps.reports.crypto import digest, encrypt
from apps.reports.selectors import source_report
from apps.scopes.access import lock_identity, require_role

from .models import Publication, PublicationRemoval, RevisionWithdrawal


def remove_report_publications(org, report, *, cause, actor, tuples=None):
    """Caller owns org/report/variant locks. Never invalidate another report."""
    if cause not in {"CORRECTION", "REAPPROVAL", "WITHDRAWAL"}:
        raise ValueError("unsupported report removal")
    now, removed = timezone.now(), []
    rows = Publication.objects.select_for_update().filter(organization=org, report=report,
        revoked_at__isnull=True).order_by("id")
    for publication in rows:
        if tuples is not None and (str(publication.channel_id), publication.profile) not in tuples:
            continue
        removal, _ = PublicationRemoval.objects.get_or_create(publication=publication, defaults={
            "organization": org, "kind": "WITHDRAWN" if cause == "WITHDRAWAL" else "SUPERSEDED",
            "cause": cause, "actor": actor, "removed_at": now})
        # Existing permanent removal is never rewritten or revived.
        publication.revoked_at = removal.removed_at
        publication.save(update_fields=["revoked_at"])
        removed.append(str(publication.id))
    return removed


@transaction.atomic
def withdraw_report(user, report_id, data, raw_body):
    actor, org = lock_identity(user)
    require_role(actor, "reviewer")
    report = source_report(actor, report_id, reviewer_only=True, lock=True)
    request_hash = digest({"route": f"POST /reports/{report_id}/withdrawal/", "body": raw_body})
    previous = RevisionWithdrawal.objects.filter(reviewer=actor, operation_id=data["operation_id"]).first()
    if previous:
        if previous.report_id != report.id or previous.request_hash != request_hash:
            raise ApiError("IDEMPOTENCY_CONFLICT", "This withdrawal operation has a different request.", 409)
        return previous.response_body
    if report.current_revision_no != data["expected_revision_no"]:
        raise ApiError("REVISION_CONFLICT", "The source revision changed. Reload before withdrawing.", 409)
    revision = report.revisions.select_for_update().get(revision_no=report.current_revision_no)
    if RevisionWithdrawal.objects.filter(revision=revision).exists():
        raise ApiError("WITHDRAWAL_CONFLICT", "This source revision was already withdrawn.", 409)
    if not isinstance(data["reason"], str) or not data["reason"].strip() or len(data["reason"]) > 500:
        raise ApiError("INVALID_REQUEST", "A private withdrawal reason is required.")
    publication_ids = remove_report_publications(org, report, cause="WITHDRAWAL", actor=actor)
    withdrawal_id = uuid.uuid4()
    result = {"withdrawal_id": str(withdrawal_id), "report_status": "WITHDRAWN", "publication_ids": publication_ids}
    RevisionWithdrawal.objects.create(id=withdrawal_id, organization=org, report=report, revision=revision,
        reviewer=actor, operation_id=data["operation_id"], request_hash=request_hash,
        expected_revision_no=revision.revision_no, reason_ciphertext=encrypt(data["reason"]),
        publication_ids=publication_ids, response_body=result, withdrawn_at=timezone.now())
    audit.record(org.id, actor, "PUBLICATION_WITHDRAWN", revision.id,
        operation_id=str(data["operation_id"]), revision_no=revision.revision_no)
    return result
