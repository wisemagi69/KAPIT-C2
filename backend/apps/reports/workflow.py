"""Allowlisted private progress metadata, after current source authorization."""
from apps.publications.models import Publication
from apps.publications.selectors import valid_publication
from .regeneration import current_job, latest_variants, representative_variant


def revision_workflow(report, revision, org):
    variant = representative_variant(revision)
    job = variant.job if variant is not None else current_job(revision)
    if variant is None and job is None:
        # Current queue eligibility and historical approval are different facts.
        # Preserve an actual prior approval/time when its output is unavailable;
        # a replacement pending job still shows NOT_READY until it prepares.
        variant = next((value for value in latest_variants(revision)
                        if value.state == "APPROVED" and getattr(value, "decision", None) is not None), None)
    decision = getattr(variant, "decision", None) if variant is not None else None
    review_state = "NOT_READY"
    if variant is not None and variant.state == "CANDIDATE" and decision is None:
        review_state = "AWAITING_REVIEW"
    elif decision is not None:
        expected_state = {"APPROVE": "APPROVED", "RETURN": "RETURNED", "REJECT": "REJECTED"}.get(decision.action)
        if variant.state == expected_state:
            review_state = expected_state
    is_current = revision.revision_no == report.current_revision_no
    sharing_state, published_at = "NOT_SHARED", None
    if review_state == "APPROVED":
        publications = list(Publication.objects.filter(
            organization_id=org.id, report_id=report.id, variant_id=variant.id, decision_id=decision.id,
        ).select_related("channel", "report__unit", "variant__revision__report", "variant__policy", "variant__job", "decision").order_by("published_at", "id"))
        if publications:
            published_at = publications[0].published_at.isoformat()
        if not is_current:
            sharing_state = "SUPERSEDED"
        elif publications and all(value.revoked_at is not None for value in publications):
            sharing_state = "WITHDRAWN"
        elif job is not None and any(valid_publication(value, org) for value in publications):
            sharing_state = "AVAILABLE"
        else:
            sharing_state = "UNAVAILABLE"
    return {
        "revision_no": revision.revision_no,
        "is_current": is_current,
        "received_at": revision.received_at.isoformat(),
        "processing": {"state": job.status if job is not None else "FAILED",
                       "attempts": max(0, job.attempts) if job is not None else 0},
        "review": {"state": review_state, "prepared_at": variant.created_at.isoformat() if variant is not None else None,
                   "decided_at": decision.recorded_at.isoformat() if decision is not None else None},
        "sharing": {"state": sharing_state, "published_at": published_at},
    }
