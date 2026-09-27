from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView


@api_view(["GET"])
@permission_classes([AllowAny])
def public_status(request):
    return Response({"status": "operational", "version": "1.0.0"})


@api_view(["GET", "DELETE"])
def unprotected_users(request):
    if request.method == "DELETE":
        return Response({"action": "deleted", "count": 1})
    return Response([
        {"id": 1, "username": "admin", "email": "admin@company.internal", "role": "superuser"},
        {"id": 2, "username": "finance_lead", "email": "finance@company.internal", "role": "accountant"},
    ])


class SecureProfileView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response({"id": request.user.id, "username": request.user.username})
