"""Content-free activity counts over an already authorized source queryset."""
from django.db.models import Count

from apps.operations.pagination import page_result

from .regeneration import scope_memo
from .selectors import filtered_reports


ACTIVITY_STATUSES = (
    "PENDING", "PROCESSING", "AWAITING_REVIEW", "FAILED",
    "APPROVED", "RETURNED", "REJECTED",
)


def report_activity_page(queryset, options, serialize):
    # Reuse the exact list status/context rules. Only status and pagination are
    # excluded from activity; authorized scope and UTC creation dates remain.
    all_statuses = filtered_reports(queryset, {**options, "status": "ALL"})
    by_status = dict.fromkeys(ACTIVITY_STATUSES, 0)
    unclassified = 0
    for row in all_statuses.order_by().values("current_status").annotate(amount=Count("pk")):
        status, amount = row["current_status"], row["amount"]
        if status in by_status:
            by_status[status] += amount
        else:
            # Unknown internal labels never become response keys or text.
            unclassified += amount
    selected = all_statuses
    if options["status"] != "ALL":
        selected = selected.filter(current_status=options["status"])
    # Callers hold the organization lock, so per-page scope lookups can be shared.
    with scope_memo():
        result = page_result(selected, options, serialize)
    result["activity"] = {
        "total": sum(by_status.values()) + unclassified,
        "by_status": by_status,
        "unclassified": unclassified,
    }
    return result
