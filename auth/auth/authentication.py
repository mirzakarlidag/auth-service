from rest_framework_simplejwt.authentication import JWTAuthentication
from django.conf import settings


class CustomJWTAuthentication(JWTAuthentication):
    """
    Custom JWT authentication to handle token extraction and validation.
    Can be extended for additional functionality.
    """

    def authenticate(self, request):
        try:
            return super().authenticate(request)
        except Exception as e:
            # Add custom handling if needed
            raise e
