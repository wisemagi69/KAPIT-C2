from django.contrib.auth import authenticate, login, logout
from django.db import transaction
from django.middleware.csrf import get_token
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_protect
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.operations.errors import ApiError
from apps.operations.parsers import BoundedJSONParser
from apps.operations.serializers import LoginSerializer
from apps.scopes.access import lock_identity, user_object

from .serializers import ChangePasswordSerializer
from .services import change_password


class CSRFView(APIView):
    permission_classes = [AllowAny]
    authentication_classes = []

    def get(self, request):
        return Response({"csrf_token": get_token(request._request)})


@method_decorator(csrf_protect, name="dispatch")
class LoginView(APIView):
    permission_classes = [AllowAny]
    authentication_classes = []
    parser_classes = [BoundedJSONParser]

    def post(self, request):
        data = LoginSerializer(data=request.data)
        data.is_valid(raise_exception=True)
        actor = authenticate(request=request._request, **data.validated_data)
        if actor is None:
            raise ApiError("LOGIN_FAILED", "The username or password was not accepted.", 401)
        with transaction.atomic():
            actor, _ = lock_identity(actor)
            result = user_object(actor)
            # Django updates last_login during login(); preserve org-before-user
            # lock order for this framework write as well.
            login(request._request, actor)
        return Response({"user": result})


class MeView(APIView):
    def get(self, request):
        with transaction.atomic():
            actor, _ = lock_identity(request.user)
            return Response({"user": user_object(actor)})


@method_decorator(csrf_protect, name="dispatch")
class LogoutView(APIView):
    # Clearing this browser's session must remain possible after the server has
    # expired/revoked identity. Explicit CSRF protection also covers AnonymousUser,
    # which DRF SessionAuthentication alone would not protect.
    permission_classes = [AllowAny]

    def post(self, request):
        logout(request._request)
        return Response({"logged_out": True})


@method_decorator(csrf_protect, name="dispatch")
class ChangePasswordView(APIView):
    parser_classes = [BoundedJSONParser]

    def post(self, request):
        serializer = ChangePasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        result = change_password(request.user, serializer.validated_data)
        # The credential/version/audit transaction has committed. Flush this
        # browser too; never preserve a session with update_session_auth_hash.
        logout(request._request)
        return Response(result)
