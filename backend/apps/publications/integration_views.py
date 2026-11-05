"""Atomic integration projections with principal-bound, timestamp-free cursors."""
from django.core import signing
from django.core.exceptions import ValidationError
from django.db import transaction
from django.http import JsonResponse
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.accounts import integration_auth as auth
from apps.audit import service as audit
from apps.operations.errors import ApiError, missing
from apps.operations.pagination import query_values
from apps.reports.crypto import digest
from apps.scopes.models import ChannelSource
from . import selectors
from .delivery import record_deliveries
from .models import Publication, PublicationDelivery


def invalid_cursor():
    return ApiError("INVALID_CURSOR", "Use a current cursor for this integration request.")


def options(params, surface):
    values = query_values(params, {"cursor", "limit", "category", "urgency", "area"} if surface == "feed" else {"cursor"})
    limit = values.get("limit", "25")
    if not isinstance(limit, str) or len(limit) > 3 or not limit.isascii() or not limit.isdecimal() or not 1 <= int(limit) <= 100:
        raise ApiError("INVALID_FILTER", "Use a limit between 1 and 100.")
    result = {"limit": int(limit), "q": "", "category": values.get("category", "ALL"), "urgency": values.get("urgency", "ALL"), "area": values.get("area", "ALL")}
    if (result["category"] not in {"ALL", "INFRASTRUCTURE", "WATER_SUPPLY", "EQUIPMENT"}
            or result["urgency"] not in {"ALL", "ROUTINE", "PRIORITY"}
            or result["area"] not in {"ALL", "Area A", "Area B", "Area C"}):
        raise ApiError("INVALID_FILTER", "Use supported integration filters.")
    cursor = values.get("cursor")
    if cursor is not None and (not isinstance(cursor, str) or not 1 <= len(cursor) <= 4096):
        raise invalid_cursor()
    return result, cursor


def cursor_context(client, org, surface, opts):
    sources = ChannelSource.objects.filter(organization=org, channel_id=client.channel_id, unit__organization=org, active=True).order_by("unit_id").values_list("unit_id", "unit__scope_epoch")
    return {"client_id": str(client.id), "channel_id": str(client.channel_id), "profile_ceiling": client.profile_ceiling,
            "policy_id": str(org.active_policy_id), "policy_epoch": org.policy_epoch,
            "scope_epochs_digest": digest([[str(unit), epoch] for unit, epoch in sources]),
            "filter_digest": digest({"surface": surface, **opts})}


def position(cursor, context, client, org):
    if cursor is None:
        return None
    try:
        value = signing.loads(cursor, salt="kapit.integration.cursor", max_age=900)
        if not isinstance(value, dict) or set(value) != set(context) | {"last_publication_id"} or any(value[key] != expected for key, expected in context.items()):
            raise ValueError
        identifier = value["last_publication_id"]
        if not isinstance(identifier, str):
            raise ValueError
        delivered = PublicationDelivery.objects.filter(organization=org, client=client, user__isnull=True,
            channel_id=client.channel_id, publication_id=identifier).select_related("publication").first()
        if delivered is None:
            raise ValueError
        return delivered.publication
    except (signing.BadSignature, ValidationError, ValueError, TypeError, KeyError):
        raise invalid_cursor() from None


def next_cursor(context, publication):
    return signing.dumps({**context, "last_publication_id": str(publication.id)}, salt="kapit.integration.cursor", compress=True)


class IntegrationView(APIView):
    authentication_classes = []
    permission_classes = []
    http_method_names = ["get"]

    def dispatch(self, request, *args, **kwargs):
        # HEAD/OPTIONS and writes have no authentication, counter, audit or ledger side effect.
        if request.method != "GET":
            response = JsonResponse({"code": "METHOD_NOT_ALLOWED", "message": "Use GET for this endpoint."}, status=405)
            response["Allow"] = "GET"
            response["Cache-Control"] = "no-store"
            return response
        return super().dispatch(request, *args, **kwargs)

    def finalize_response(self, request, response, *args, **kwargs):
        response = super().finalize_response(request, response, *args, **kwargs)
        response["Cache-Control"] = "no-store"
        if response.status_code == 401:
            response["WWW-Authenticate"] = 'Bearer realm="kapit-integration"'
        return response

    def get(self, request, **kwargs):
        try:
            client = auth.candidate(request)
            with transaction.atomic():
                client, org, scope = auth.lock_client(client)
                result = self.read(request, client, org, scope, **kwargs)
                audit.record(org.id, None, "INTEGRATION_READ", client.id)
                return Response(result)
        except ApiError as error:
            if error.status_code == 401:
                auth.record_failure(request)
            raise


class IntegrationFeedView(IntegrationView):
    def read(self, request, client, org, scope):
        opts, cursor = options(request.query_params, "feed")
        context = cursor_context(client, org, "feed", opts)
        after = position(cursor, context, client, org)
        _, chosen = selectors.selected_publications(None, org, client.channel_id, client=client)
        values = selectors.filtered_publications(scope, chosen, opts)
        if after is not None:
            values = [value for value in values if (value.published_at, value.id) < (after.published_at, after.id)]
        page = values[:opts["limit"]]
        record_deliveries(None, org, page, client=client)
        return {"results": [selectors.serialize_publication(row) for row in page],
                "next_cursor": next_cursor(context, page[-1]) if page and len(values) > len(page) else None}


class IntegrationDetailView(IntegrationView):
    def read(self, request, client, org, scope, publication_id):
        if request.query_params:
            raise ApiError("INVALID_FILTER", "Filters are unavailable for this endpoint.")
        target = selectors.current_dataset(None, org, client=client).filter(pk=publication_id).first()
        if target is None:
            raise missing()
        _, chosen = selectors.selected_publications(None, org, client.channel_id, target.profile, client=client)
        if not any(row.id == target.id for row in chosen):
            raise missing()
        record_deliveries(None, org, [target], client=client)
        return selectors.serialize_publication(target)


class IntegrationRemovedView(IntegrationView):
    def read(self, request, client, org, scope):
        opts, cursor = options(request.query_params, "removed")
        context = cursor_context(client, org, "removed", opts)
        after = position(cursor, context, client, org)
        removed = selectors.removed_for_scope(None, org, scope)["results"]
        ids = [row["publication_id"] for row in removed]
        rows = list(Publication.objects.filter(organization=org, channel_id=client.channel_id, pk__in=ids).order_by("-published_at", "-id"))
        if after is not None:
            rows = [row for row in rows if (row.published_at, row.id) < (after.published_at, after.id)]
        page = rows[:25]
        return {"results": [{"publication_id": str(row.id), "state": "WITHDRAWN"} for row in page],
                "next_cursor": next_cursor(context, page[-1]) if page and len(rows) > len(page) else None}
