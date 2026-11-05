from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_protect
from rest_framework.exceptions import APIException, AuthenticationFailed, NotAuthenticated
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.operations.errors import ApiError, api_exception_handler

from .mobile_authentication import MobileAuthentication
from .mobile_protocol import (MobileError, MobileJSONParser, ChallengeSerializer, TokenSerializer,
    RefreshSerializer, EmptySerializer, config)
from .mobile_services import (issue_challenge, complete_proof, rotate_refresh, mobile_context,
    logout_mobile, list_devices, revoke_device)
from .mobile_throttle import consume


def forbid_queries(request):
    if request.query_params:
        raise ApiError("INVALID_FILTER", "Query parameters are not accepted.")


class MobileView(APIView):
    authentication_classes = [MobileAuthentication]
    parser_classes = [MobileJSONParser]

    def initial(self, request, *args, **kwargs):
        config()
        super().initial(request, *args, **kwargs)
        forbid_queries(request)

    def handle_exception(self, exc):
        if isinstance(exc, (AuthenticationFailed, NotAuthenticated)):
            exc = MobileError()
        if isinstance(exc, MobileError):
            return Response(exc.safe_body, status=exc.status_code, headers=exc.headers)
        if isinstance(exc, APIException):
            return api_exception_handler(exc, self.get_exception_handler_context())
        # No raw DB, crypto, audit or parser internals cross this boundary.
        failure = MobileError("SERVER_ERROR", 503)
        return Response(failure.safe_body, status=503)

    def finalize_response(self, request, response, *args, **kwargs):
        response = super().finalize_response(request, response, *args, **kwargs)
        response["Cache-Control"] = "private, no-store"
        return response


class PublicAuthView(MobileView):
    authentication_classes = []
    permission_classes = [AllowAny]

    def initial(self, request, *args, **kwargs):
        config()
        # Use the actual socket peer; never trust forwarding headers.
        peer = request.META.get("REMOTE_ADDR", "unknown")
        consume("peer", peer if isinstance(peer, str) and len(peer) <= 64 else "unknown", 30)
        super().initial(request, *args, **kwargs)


class ChallengeView(PublicAuthView):
    def post(self, request):
        body = request.data
        username = body.get("username")
        consume("username", username if isinstance(username, str) else "<invalid>", 10)
        serializer = ChallengeSerializer(data=body)
        serializer.is_valid(raise_exception=True)
        return Response(issue_challenge(serializer.validated_data))


class TokenView(PublicAuthView):
    def post(self, request):
        serializer = TokenSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response(complete_proof(serializer.validated_data))


class RefreshView(PublicAuthView):
    def post(self, request):
        serializer = RefreshSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response(rotate_refresh(serializer.validated_data["refresh_token"]))


class MeView(MobileView):
    def get(self, request):
        return Response(mobile_context(request.auth))


class LogoutView(MobileView):
    def post(self, request):
        serializer = EmptySerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response(logout_mobile(request.auth))


class DevicesView(APIView):
    parser_classes = [MobileJSONParser]

    def get(self, request):
        forbid_queries(request)
        return Response(list_devices(request.user))


@method_decorator(csrf_protect, name="dispatch")
class RevokeDeviceView(APIView):
    parser_classes = [MobileJSONParser]

    def post(self, request, enrollment_id):
        forbid_queries(request)
        serializer = EmptySerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response(revoke_device(request.user, enrollment_id))
