from django.db.models import Case, CharField, Exists, F, Func, JSONField, OuterRef, Q, Subquery, Value, When

from apps.operations.errors import missing
from apps.operations.models import ProcessingJob, SyncReceipt
from apps.scopes.access import live_memberships, source_allowed
from apps.scopes.models import ChannelSource
from apps.publications.models import RevisionWithdrawal

from .crypto import decrypt, digest, source_payload
from .models import Report, ReportRevision, ReportVariant
from .services import receipt_body
from .regeneration import current_job, latest_job, representative_variant
from .projection import POLICIES


def source_report(actor, report_id, reviewer_only=False, lock=False):
    queryset = Report.objects.filter(pk=report_id, organization_id=actor.organization_id)
    if lock:
        queryset = queryset.select_for_update()
    report = queryset.first()
    if report is None or not source_allowed(actor, report, reviewer_only):
        raise missing()
    return report


def summary(report, revision=None):
    revision = revision or report.revisions.get(revision_no=report.current_revision_no)
    payload = source_payload(revision)
    job = current_job(revision)
    variant = representative_variant(revision, job) if job is not None else None
    state = revision.processing_state if job is not None else "FAILED"
    feedback = None
    if variant is not None:
        state = {"CANDIDATE": "AWAITING_REVIEW", "APPROVED": "APPROVED", "RETURNED": "RETURNED", "REJECTED": "REJECTED"}[variant.state]
        if variant.state in {"RETURNED", "REJECTED"}:
            decision = getattr(variant, "decision", None)
            feedback = decrypt(decision.reason_ciphertext) if decision and decision.reason_ciphertext else None
    return {"id": str(report.id), "reference": "R-" + report.id.hex[:8].upper(),
            "category": payload["category"], "urgency": payload["urgency"], "area_label": payload["area_label"],
            "created_at": report.created_at.isoformat(), "observed_date": revision.observed_at.date().isoformat(),
            "revision_no": revision.revision_no, "status": state, "variant_id": str(variant.id) if variant else None, "feedback": feedback}


def own_reports(actor):
    units = live_memberships(actor, "submitter").values("unit_id")
    return Report.objects.filter(organization_id=actor.organization_id, author=actor, unit_id__in=units).order_by("-created_at", "-id")


def review_reports(actor):
    units = live_memberships(actor, "reviewer").values("unit_id")
    return Report.objects.filter(
        organization_id=actor.organization_id, unit_id__in=units,
    ).exclude(author=actor).order_by("-created_at", "-id")


def filtered_reports(queryset, options):
    # Correlate both candidate and processing state to the current pointer.
    # Filtering and counting never decrypt source content or load other pages.
    revisions = ReportRevision.objects.filter(report_id=OuterRef("pk"), revision_no=OuterRef("current_revision_no"))
    jobs = ProcessingJob.objects.filter(revision__report_id=OuterRef("pk"), revision__revision_no=OuterRef("current_revision_no")).order_by(
        "-policy_epoch", "-scope_epoch", "-available_at", "-id")
    # SQL mirrors current_job's live context selection and terminal-decision exception.
    jobs = jobs.annotate(
        has_open=Exists(ReportVariant.objects.filter(job_id=OuterRef("pk"), state__in=["CANDIDATE", "APPROVED"])),
        has_terminal=Exists(ReportVariant.objects.filter(job_id=OuterRef("pk"), state__in=["RETURNED", "REJECTED"])),
        is_withdrawn=Exists(RevisionWithdrawal.objects.filter(revision_id=OuterRef("revision_id"), organization_id=OuterRef("organization_id"))),
        has_eligible=Exists(ChannelSource.objects.filter(unit_id=OuterRef("revision__report__unit_id"),
            organization_id=OuterRef("organization_id"), active=True, unit__active=True,
            channel__organization_id=OuterRef("organization_id"), channel__active=True)),
        live_context=Func(OuterRef("unit_id"), function="kapit_scope_context", output_field=JSONField()),
    )
    supported = Q(pk__isnull=True)
    for version, rules in POLICIES.items():
        supported |= Q(policy__version=version, policy__rules=rules, policy__rules_hash=digest(rules))
    live = (Q(policy_id=OuterRef("organization__active_policy_id"), policy__active=True,
        policy_epoch=OuterRef("organization__policy_epoch"), scope_epoch=OuterRef("unit__scope_epoch"),
        revision__report__unit__active=True, has_eligible=True, is_withdrawn=False)
        & (Q(scope_context=F("live_context")) | Q(scope_context__isnull=True, live_context__isnull=True)) & supported)
    jobs = jobs.filter(live | Q(has_terminal=True, has_open=False))
    variants = ReportVariant.objects.filter(job_id=OuterRef("current_job_id")).annotate(status_order=Case(
        When(state="APPROVED", then=Value(0)), When(state="CANDIDATE", then=Value(1)),
        When(state="RETURNED", then=Value(2)), default=Value(3))).order_by("status_order", "profile", "id")
    queryset = queryset.annotate(
        current_job_id=Subquery(jobs.values("id")[:1]),
        current_processing=Subquery(revisions.values("processing_state")[:1]),
    ).annotate(
        current_variant_state=Subquery(variants.values("state")[:1]),
    ).annotate(current_status=Case(
        When(current_variant_state="CANDIDATE", then=Value("AWAITING_REVIEW")),
        When(current_variant_state="APPROVED", then=Value("APPROVED")),
        When(current_variant_state="RETURNED", then=Value("RETURNED")),
        When(current_variant_state="REJECTED", then=Value("REJECTED")),
        When(current_job_id__isnull=True, then=Value("FAILED")),
        default="current_processing", output_field=CharField(),
    ))
    if options["status"] != "ALL":
        queryset = queryset.filter(current_status=options["status"])
    if "date_from" in options:
        queryset = queryset.filter(created_at__date__gte=options["date_from"])
    if "date_to" in options:
        queryset = queryset.filter(created_at__date__lte=options["date_to"])
    return queryset


def returned_revision(revision):
    job = current_job(revision)
    return bool(job and job.variants.filter(state="RETURNED", decision__action="RETURN").exists())


def can_correct(actor, report, revision):
    return (actor.role == "submitter" and report.author_id == actor.id
            and revision.revision_no == report.current_revision_no
            and source_allowed(actor, report) and returned_revision(revision))


def revision_history(report):
    result = []
    for revision in report.revisions.order_by("-revision_no").prefetch_related("variants"):
        variant = representative_variant(revision)
        state = revision.processing_state if current_job(revision) is not None else "FAILED"
        if variant:
            state = "AWAITING_REVIEW" if variant.state == "CANDIDATE" else variant.state
        result.append({"revision_no": revision.revision_no, "received_at": revision.received_at.isoformat(), "status": state})
    return result


def authorized_receipt(actor, operation_id, *, accepted_device=None):
    # NULL is deliberately the web namespace; mobile never falls through to it.
    receipt = SyncReceipt.objects.filter(accepted_user=actor, accepted_device=accepted_device,
        organization_id=actor.organization_id, operation_id=operation_id).select_related("revision__report").first()
    if receipt is not None:
        if not source_allowed(actor, receipt.revision.report):
            raise missing()
        return receipt.response_body
    revision = ReportRevision.objects.filter(submitted_by=actor, accepted_device=accepted_device,
        operation_id=operation_id, organization_id=actor.organization_id).select_related("report").first()
    if revision is None or not source_allowed(actor, revision.report):
        raise missing()
    return receipt_body(revision)
