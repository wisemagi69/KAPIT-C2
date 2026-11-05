from django.http import JsonResponse
from rest_framework.exceptions import APIException, AuthenticationFailed, NotAuthenticated, NotFound, PermissionDenied, ValidationError
from rest_framework.response import Response
from rest_framework.views import exception_handler


class ApiError(APIException):
    def __init__(self, code, message, status=400, errors=None):
        self.status_code = status
        self.safe_body = {"code": code, "message": message}
        if errors is not None:
            self.safe_body["errors"] = errors
        super().__init__(message)


def missing():
    return ApiError("NOT_FOUND", "This item is unavailable.", 404)


def forbidden():
    return ApiError("ACCESS_DENIED", "Your current account cannot perform this action.", 403)


def api_exception_handler(exc, context):
    if isinstance(exc, ApiError):
        return Response(exc.safe_body, status=exc.status_code)
    response = exception_handler(exc, context)
    if isinstance(exc, ValidationError):
        return Response({"code": "VALIDATION_ERROR", "message": "Check the highlighted fields.", "errors": response.data}, status=422)
    if isinstance(exc, (NotAuthenticated, AuthenticationFailed)):
        return Response({"code": "AUTH_REQUIRED", "message": "Sign in to continue."}, status=403)
    if isinstance(exc, PermissionDenied):
        code = "CSRF_FAILED" if str(exc.detail).startswith("CSRF Failed") else "ACCESS_DENIED"
        return Response({"code": code, "message": "Refresh your session and try again." if code == "CSRF_FAILED" else "This action is unavailable."}, status=403)
    if isinstance(exc, NotFound):
        return Response(missing().safe_body, status=404)
    if response is not None:
        return Response({"code": "INVALID_REQUEST", "message": "This request could not be accepted."}, status=response.status_code)
    return Response({"code": "SERVER_ERROR", "message": "The service is unavailable. Retry the same operation later."}, status=500)


def csrf_failure(request, reason=""):
    return JsonResponse({"code": "CSRF_FAILED", "message": "Refresh your session and try again."}, status=403)
