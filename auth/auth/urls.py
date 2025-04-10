from django.contrib import admin
from django.urls import path
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
    TokenVerifyView,
)
from django.contrib.auth import views as auth_views
from .views import (
    UserRegistrationView,
    UserListView,
    UserDetailView,
    ChangePasswordView,
    LogoutView,
)

urlpatterns = [
    path("admin/", admin.site.urls),
    # JWT endpoints
    path("api/token/", TokenObtainPairView.as_view(), name="token_obtain_pair"),
    path("api/token/refresh/", TokenRefreshView.as_view(), name="token_refresh"),
    path("api/token/verify/", TokenVerifyView.as_view(), name="token_verify"),
    # User management
    path("api/users/register/", UserRegistrationView.as_view(), name="register"),
    path("api/users/", UserListView.as_view(), name="user-list"),
    path("api/users/<int:pk>/", UserDetailView.as_view(), name="user-detail"),
    path(
        "api/users/change-password/",
        ChangePasswordView.as_view(),
        name="change-password",
    ),
    path("api/users/logout/", LogoutView.as_view(), name="logout"),
]
