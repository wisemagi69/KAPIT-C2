"""Owner-only browser device controls; mounting belongs to integration."""
from django.urls import path

from .mobile_views import DevicesView, RevokeDeviceView

urlpatterns = [
    path("devices/", DevicesView.as_view()),
    path("devices/<uuid:enrollment_id>/revoke/", RevokeDeviceView.as_view()),
]
