"""M3 recipient adapters; new map/removed routes remain unmounted until integration."""
from django.db import transaction
from django.utils import timezone
from rest_framework.response import Response

from apps.audit import service as audit
from apps.operations.views import BusinessView
from apps.scopes.access import lock_identity
from . import selectors


class FeedView(BusinessView):
    def get(self, request, channel_id):
        with transaction.atomic():
            actor, org = lock_identity(request.user)
            result = selectors.feed(actor, org, channel_id, request.query_params)
            audit.record(org.id, actor, "RECIPIENT_FEED_READ")
            return Response({**result, "refreshed_at": timezone.now().isoformat()})


class PublicationView(BusinessView):
    def get(self, request, publication_id):
        self.forbid_filters(request)
        with transaction.atomic():
            actor, org = lock_identity(request.user)
            result = selectors.detail(actor, org, publication_id)
            audit.record(org.id, actor, "PUBLICATION_READ", publication_id)
            return Response(result)


class MapView(BusinessView):
    def get(self, request, channel_id):
        with transaction.atomic():
            actor, org = lock_identity(request.user)
            result = selectors.map_counts(actor, org, channel_id, request.query_params)
            audit.record(org.id, actor, "RECIPIENT_MAP_READ")
            return Response(result)


class RemovedView(BusinessView):
    def get(self, request, channel_id):
        self.forbid_filters(request)
        with transaction.atomic():
            actor, org = lock_identity(request.user)
            result = selectors.removed(actor, org, channel_id)
            audit.record(org.id, actor, "RECIPIENT_REMOVED_READ")
            return Response(result)
