"""Explicit URL configuration for the separately owned local M2 runtime only."""
from django.urls import include, path

urlpatterns = [
    path("api/v1/mobile/", include("apps.accounts.mobile_urls")),
    path("api/v1/mobile/", include("apps.operations.mobile_urls")),
    path("api/v1/account/", include("apps.accounts.device_urls")),
    path("", include("config.urls")),
]

handler400 = "config.errors.bad_request"
handler403 = "config.errors.permission_denied"
handler404 = "config.errors.not_found"
handler500 = "config.errors.server_error"
