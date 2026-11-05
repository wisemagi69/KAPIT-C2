"""Private durable delivery metadata; caller owns the same atomic authorized read."""
from django.db import DatabaseError, transaction
from django.utils import timezone

from apps.operations.errors import ApiError, missing
from .models import PublicationDelivery


def record_deliveries(actor, org, publications, *, client=None):
    if (actor is None) == (client is None):
        raise missing()
    principal = {"user": actor, "client": None} if client is None else {"client": client, "user": None}
    identity = actor if actor is not None else client
    if identity.organization_id != org.id:
        raise missing()
    try:
        with transaction.atomic():
            for publication in publications:
                if publication.organization_id != org.id:
                    raise missing()
                delivered, _ = PublicationDelivery.objects.get_or_create(publication=publication, **principal,
                    defaults={"organization": org, "channel": publication.channel, "profile": publication.profile,
                              "first_delivered_at": timezone.now()})
                if (delivered.organization_id != org.id or delivered.channel_id != publication.channel_id
                        or delivered.profile != publication.profile):
                    raise ApiError("SERVER_ERROR", "The service is unavailable. Retry later.", 503)
    except DatabaseError:
        raise ApiError("SERVER_ERROR", "The service is unavailable. Retry later.", 503) from None
