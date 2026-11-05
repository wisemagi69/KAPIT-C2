from django.urls import include, path

from .views import asset, website

urlpatterns = [
    path("api/v1/", include("apps.operations.urls")),
    path("api/integration/v1/", include("apps.publications.integration_urls")),
    path("assets/<str:filename>", asset),
    path("workspace", website),
    path("workspace/", website),
    path("", website),
]
handler400 = "config.errors.bad_request"
handler403 = "config.errors.permission_denied"
handler404 = "config.errors.not_found"
handler500 = "config.errors.server_error"
