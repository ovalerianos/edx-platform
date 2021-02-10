"""
URLs for the V1 of the Learner Dashboard API.
"""

from rest_framework.routers import DefaultRouter
from .views import ProgramListView
from django.conf.urls import url

app_name = 'v1'
urlpatterns = [
    url(
        r'^programs/$',
        ProgramListView.as_view(),
        name='program_listing'
    ),
]
