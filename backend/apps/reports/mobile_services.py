"""Mobile adapters retain original claims through each protected transaction."""
from django.db import transaction

from apps.accounts.mobile_services import lock_mobile_identity
from apps.audit import service as audit
from apps.operations.errors import missing
from apps.operations.pagination import page_result, report_filters

from .crypto import source_payload
from .selectors import authorized_receipt, can_correct, filtered_reports, own_reports, revision_history, source_report, summary
from .services import _accept_locked, receipt_body
from .workflow import revision_workflow


def mobile_can_correct(actor, report, revision):
    # Kept distinct from the broader web correction rule introduced by TASK-126.
    from apps.scopes.access import source_allowed
    from .selectors import returned_revision
    return (actor.role == "submitter" and report.author_id == actor.id
            and revision.revision_no == report.current_revision_no
            and source_allowed(actor, report) and returned_revision(revision))


@transaction.atomic
def accept_mobile_operation(claims, data, raw_body):
    actor, org, enrollment, _ = lock_mobile_identity(claims)
    return _accept_locked(actor, org, enrollment, data, raw_body)


@transaction.atomic
def mobile_receipt(claims, operation_id):
    actor, org, enrollment, _ = lock_mobile_identity(claims)
    result = authorized_receipt(actor, operation_id, accepted_device=enrollment)
    audit.record(org.id, actor, "MOBILE_RECEIPT_READ", operation_id)
    return result


@transaction.atomic
def mobile_reports(claims, params):
    actor, org, _, _ = lock_mobile_identity(claims)
    options = report_filters(params, "ALL")
    result = page_result(filtered_reports(own_reports(actor), options), options, summary)
    audit.record(org.id, actor, "SOURCE_LIST_READ")
    return result


@transaction.atomic
def mobile_revision(claims, report_id, revision_no):
    actor, org, _, _ = lock_mobile_identity(claims)
    report = source_report(actor, report_id)
    revision = report.revisions.filter(revision_no=revision_no).first()
    if revision is None:
        raise missing()
    result = {"report": summary(report, revision), "payload": source_payload(revision), "receipt": receipt_body(revision),
        "can_correct": mobile_can_correct(actor, report, revision), "history": revision_history(report),
        "workflow": revision_workflow(report, revision, org)}
    audit.record(org.id, actor, "ORIGINAL_READ", revision.id)
    return result
