from django.urls import include, path

from apps.accounts.views import CSRFView, ChangePasswordView, LoginView, LogoutView, MeView
from apps.accounts import administration
from apps.publications.views import FeedView, MapView, PublicationView, RemovedView
from apps.scopes.policy_views import PolicyApplyView, PolicyProposalView, PolicyStateView

from . import views
from .evidence_views import EvidenceCaptureView
from apps.review.views import BatchDecisionView, CandidateSetView, WithdrawalView


urlpatterns = [
    path("auth/csrf/", CSRFView.as_view()),
    path("auth/login/", LoginView.as_view()),
    path("auth/logout/", LogoutView.as_view()),
    path("auth/password/", ChangePasswordView.as_view()),
    path("me/", MeView.as_view()),
    path("administration/context/", administration.ContextView.as_view()),
    path("administration/health/", administration.HealthView.as_view()),
    path("administration/users/", administration.UsersView.as_view()),
    path("administration/users/<uuid:user_id>/", administration.UserView.as_view()),
    path("administration/users/<uuid:user_id>/password/", administration.PasswordView.as_view()),
    path("administration/integration-clients/", administration.IntegrationClientsView.as_view()),
    path("administration/integration-clients/requests/<uuid:object_id>/approve/", administration.IntegrationApproveView.as_view()),
    path("administration/integration-clients/requests/<uuid:object_id>/collect/", administration.IntegrationCollectView.as_view()),
    path("administration/integration-clients/<uuid:object_id>/revoke/", administration.IntegrationRevokeView.as_view()),
    path("administration/policy/", PolicyStateView.as_view()),
    path("administration/policy/proposals/", PolicyProposalView.as_view()),
    path("administration/policy/proposals/<uuid:proposal_id>/apply/", PolicyApplyView.as_view()),
    path("sync/operations/", views.OperationsView.as_view()),
    path("sync/receipts/<uuid:operation_id>/", views.ReceiptView.as_view()),
    path("reports/", views.ReportsView.as_view()),
    path("reports/<uuid:report_id>/revisions/<int:revision_no>/", views.RevisionView.as_view()),
    path("reports/<uuid:report_id>/withdrawal/", WithdrawalView.as_view()),
    path("revisions/<uuid:revision_id>/candidates/", CandidateSetView.as_view()),
    path("revisions/<uuid:revision_id>/decisions/", BatchDecisionView.as_view()),
    path("review/queue/", views.QueueView.as_view()),
    path("variants/<uuid:variant_id>/review/", views.ReviewView.as_view()),
    path("variants/<uuid:variant_id>/decisions/", views.DecisionView.as_view()),
    path("channels/<uuid:channel_id>/feed/", FeedView.as_view()),
    path("channels/<uuid:channel_id>/map/", MapView.as_view()),
    path("channels/<uuid:channel_id>/removed/", RemovedView.as_view()),
    path("publications/<uuid:publication_id>/", PublicationView.as_view()),
    path("evidence/<uuid:evidence_id>/capture/", EvidenceCaptureView.as_view()),
    path("", include("apps.operations.evidence_urls")),
]
