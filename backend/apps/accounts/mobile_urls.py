"""Inactive until the owned integration harness explicitly mounts this module."""
from django.urls import path

from .mobile_views import ChallengeView, TokenView, RefreshView, MeView, LogoutView

urlpatterns = [
    path("auth/challenge/", ChallengeView.as_view()),
    path("auth/token/", TokenView.as_view()),
    path("auth/refresh/", RefreshView.as_view()),
    path("auth/logout/", LogoutView.as_view()),
    path("me/", MeView.as_view()),
]
