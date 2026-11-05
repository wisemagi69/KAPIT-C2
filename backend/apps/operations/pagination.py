"""Strict bounded query parameters shared by scoped business lists."""
import re
from datetime import date

from .errors import ApiError


SOURCE_STATUSES = {"ALL", "PENDING", "PROCESSING", "AWAITING_REVIEW", "FAILED", "APPROVED", "RETURNED", "REJECTED"}


def query_values(params, allowed):
    if set(params) - set(allowed) or any(len(params.getlist(key)) != 1 for key in params):
        raise ApiError("INVALID_FILTER", "Use only supported filters, each once.")
    return params.dict()


def pagination_values(values):
    result = {}
    for name, default, maximum in [("page", 1, 2147483647), ("page_size", 10, 50)]:
        text = values.get(name, str(default))
        if not re.fullmatch(r"[1-9][0-9]{0,9}", text) or int(text) > maximum:
            raise ApiError("INVALID_FILTER", "Page and page size must be positive bounded integers.")
        result[name] = int(text)
    return result


def report_filters(params, default_status):
    values = query_values(params, {"status", "date_from", "date_to", "page", "page_size"})
    result = pagination_values(values)
    result["status"] = values.get("status", default_status)
    if result["status"] not in SOURCE_STATUSES:
        raise ApiError("INVALID_FILTER", "Choose a supported report status.")
    for name in ["date_from", "date_to"]:
        text = values.get(name)
        if text is not None:
            try:
                if not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", text):
                    raise ValueError
                result[name] = date.fromisoformat(text)
            except ValueError:
                raise ApiError("INVALID_FILTER", "Use valid UTC dates in YYYY-MM-DD format.") from None
    if result.get("date_from", date.min) > result.get("date_to", date.max):
        raise ApiError("INVALID_FILTER", "The start date must not follow the end date.")
    return result


def page_result(queryset, options, serialize):
    count = queryset.count()
    page, size = options["page"], options["page_size"]
    offset = (page - 1) * size
    return {"results": [serialize(row) for row in queryset[offset:offset + size]],
            "count": count, "page": page, "page_size": size,
            "total_pages": max(1, (count + size - 1) // size)}
