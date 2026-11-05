"""Safe Django-level JSON errors, including failures outside DRF."""
from django.http import JsonResponse


def bad_request(request, exception=None):
    return JsonResponse({"code": "INVALID_REQUEST", "message": "This request could not be accepted."}, status=400)


def permission_denied(request, exception=None):
    return JsonResponse({"code": "ACCESS_DENIED", "message": "This action is unavailable."}, status=403)


def not_found(request, exception=None):
    return JsonResponse({"code": "NOT_FOUND", "message": "This resource is unavailable."}, status=404)


def server_error(request):
    return JsonResponse({"code": "SERVER_UNAVAILABLE", "message": "The request could not be completed. Please try again."}, status=500)


def csrf_failure(request, reason=""):
    return JsonResponse({"code": "CSRF_FAILED", "message": "Refresh this page before trying again."}, status=403)
