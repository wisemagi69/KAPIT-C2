"""Isolated URL module; mounting requires the parent's reviewed integration."""
from django.urls import path

from .evidence_views import EvidenceDownloadView, EvidenceMetadataView, EvidenceUploadView, EvidenceValidationStatusView


urlpatterns = [
    path("revisions/<uuid:revision_id>/evidence/", EvidenceUploadView.as_view()),
    path("evidence/<uuid:evidence_id>/", EvidenceMetadataView.as_view()),
    path("evidence/<uuid:evidence_id>/download/", EvidenceDownloadView.as_view()),
    path("evidence/<uuid:evidence_id>/validation/", EvidenceValidationStatusView.as_view()),
]
