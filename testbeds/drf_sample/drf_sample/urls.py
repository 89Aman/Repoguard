from django.urls import path
from drf_sample import views

urlpatterns = [
    path("api/public-status/", views.public_status),
    path("api/unprotected-users/", views.unprotected_users),
    path("api/secure-profile/", views.SecureProfileView.as_view()),
]
