from django.db import transaction
from rest_framework.authentication import BaseAuthentication, get_authorization_header

from .mobile_protocol import AUTH_HEADER, MobileError, config, decode_access
from .mobile_services import lock_mobile_identity


class MobileAuthentication(BaseAuthentication):
    def authenticate(self, request):
        config()
        header = get_authorization_header(request)
        try:
            parts = header.decode("ascii").split(" ")
            if len(parts) != 2 or parts[0] != "Bearer" or not parts[1]:
                raise ValueError
        except (ValueError, UnicodeError):
            raise MobileError() from None
        claims = decode_access(parts[1])
        with transaction.atomic():
            actor, _, _, _ = lock_mobile_identity(claims)
        # Each business service rechecks these original claims under its own
        # transaction, so revocation between authentication and dispatch wins.
        return actor, claims

    def authenticate_header(self, request):
        return AUTH_HEADER
