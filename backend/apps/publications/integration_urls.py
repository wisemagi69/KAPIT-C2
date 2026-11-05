"""Read-only integration URL package; TASK-130 owns its configuration mount."""
from django.urls import path

from .integration_views import IntegrationDetailView, IntegrationFeedView, IntegrationRemovedView

urlpatterns = [
    path("publications/", IntegrationFeedView.as_view()),
    path("publications/<uuid:publication_id>/", IntegrationDetailView.as_view()),
    path("removed/", IntegrationRemovedView.as_view()),
]
