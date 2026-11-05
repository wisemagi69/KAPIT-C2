"""Inactive mobile report routes; the owned integration task mounts these."""
from django.urls import path

from .mobile_views import MobileOperationsView, MobileReceiptView, MobileReportsView, MobileRevisionView
from .mobile_evidence import MobileEvidenceUploadView, MobileEvidenceCaptureView, MobileEvidenceValidationView

urlpatterns = [
    path("revisions/<uuid:revision_id>/evidence/", MobileEvidenceUploadView.as_view()),
    path("evidence/<uuid:evidence_id>/capture/", MobileEvidenceCaptureView.as_view()),
    path("evidence/<uuid:evidence_id>/validation/", MobileEvidenceValidationView.as_view()),
    path("sync/operations/", MobileOperationsView.as_view()),
    path("sync/receipts/<uuid:operation_id>/", MobileReceiptView.as_view()),
    path("reports/", MobileReportsView.as_view()),
    path("reports/<uuid:report_id>/revisions/<int:revision_no>/", MobileRevisionView.as_view()),
]
