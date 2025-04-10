from rest_framework import permissions
from django.conf import settings
from django.contrib.auth.models import Group


def get_user_role(user):
    """Helper function to get the primary role of a user."""
    if user.is_superuser:
        return settings.USER_ROLES["ADMIN"]

    # Get user's groups
    groups = user.groups.all()
    if not groups:
        return settings.USER_ROLES["USER"]  # Default role

    # Priority order: admin > dev > tester > user
    role_priority = [
        settings.USER_ROLES["ADMIN"],
        settings.USER_ROLES["DEV"],
        settings.USER_ROLES["TESTER"],
        settings.USER_ROLES["USER"],
    ]

    # Return the highest priority role the user has
    for role in role_priority:
        if groups.filter(name=role).exists():
            return role

    return settings.USER_ROLES["USER"]  # Default fallback


class IsAdmin(permissions.BasePermission):
    """
    Permission to only allow administrators access.
    """

    def has_permission(self, request, view):
        return request.user.is_authenticated and (
            request.user.is_superuser
            or request.user.groups.filter(name=settings.USER_ROLES["ADMIN"]).exists()
        )


class IsDeveloper(permissions.BasePermission):
    """
    Permission to only allow developers access.
    """

    def has_permission(self, request, view):
        if not request.user.is_authenticated:
            return False

        # Admins also have developer privileges
        if (
            request.user.is_superuser
            or request.user.groups.filter(name=settings.USER_ROLES["ADMIN"]).exists()
        ):
            return True

        return request.user.groups.filter(name=settings.USER_ROLES["DEV"]).exists()


class IsTester(permissions.BasePermission):
    """
    Permission to only allow testers access.
    """

    def has_permission(self, request, view):
        if not request.user.is_authenticated:
            return False

        # Admins and developers also have tester privileges
        if (
            request.user.is_superuser
            or request.user.groups.filter(
                name__in=[settings.USER_ROLES["ADMIN"], settings.USER_ROLES["DEV"]]
            ).exists()
        ):
            return True

        return request.user.groups.filter(name=settings.USER_ROLES["TESTER"]).exists()
