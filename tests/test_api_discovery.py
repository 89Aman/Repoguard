import tempfile
from pathlib import Path
from repoguard.api.discovery import discover_api_endpoints
from repoguard.core.models import EndpointAuthStatus


def test_django_and_drf_api_discovery():
    with tempfile.TemporaryDirectory() as tmp_dir:
        root = Path(tmp_dir)

        views_py = root / "views.py"
        views_py.write_text(
            """
from rest_framework import viewsets
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.decorators import api_view, permission_classes
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse

class SecureViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]

class InsecureViewSet(viewsets.ModelViewSet):
    permission_classes = [AllowAny]

class DefaultViewSet(viewsets.ModelViewSet):
    pass

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def protected_fn(request):
    return JsonResponse({'status': 'ok'})

@login_required
def standard_login_fn(request):
    return JsonResponse({'status': 'ok'})

def public_fn(request):
    return JsonResponse({'status': 'open'})
""",
            encoding="utf-8",
        )

        urls_py = root / "urls.py"
        urls_py.write_text(
            """
from django.urls import path
from rest_framework.routers import DefaultRouter
from . import views

router = DefaultRouter()
router.register(r'secure-items', views.SecureViewSet, basename='secure')
router.register(r'insecure-items', views.InsecureViewSet, basename='insecure')
router.register(r'default-items', views.DefaultViewSet, basename='default')

urlpatterns = [
    path('api/protected/', views.protected_fn),
    path('portal/dashboard/', views.standard_login_fn),
    path('api/public/', views.public_fn),
] + router.urls
""",
            encoding="utf-8",
        )

        endpoints, findings = discover_api_endpoints(tmp_dir)

        paths = [ep.path for ep in endpoints]
        assert "/api/protected/" in paths
        assert "/portal/dashboard/" in paths
        assert "/api/public/" in paths
        assert "/secure-items/" in paths
        assert "/insecure-items/" in paths
        assert "/default-items/" in paths

        prot_ep = next(e for e in endpoints if e.path == "/api/protected/")
        assert prot_ep.status == EndpointAuthStatus.PROTECTED
        assert not prot_ep.is_flagged

        dash_ep = next(e for e in endpoints if e.path == "/portal/dashboard/")
        assert dash_ep.status == EndpointAuthStatus.PROTECTED

        pub_ep = next(e for e in endpoints if e.path == "/api/public/")
        assert pub_ep.status in (EndpointAuthStatus.UNPROTECTED, EndpointAuthStatus.ALLOW_ANY_DEFAULT)
        assert pub_ep.is_flagged

        insecure_vs = next(e for e in endpoints if e.path == "/insecure-items/")
        assert insecure_vs.is_flagged

        assert len(findings) >= 2
