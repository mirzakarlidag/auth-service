from django.contrib.auth.models import User, Group
from rest_framework import serializers
from django.conf import settings


class GroupSerializer(serializers.ModelSerializer):
    class Meta:
        model = Group
        fields = ["id", "name"]


class UserSerializer(serializers.ModelSerializer):
    groups = GroupSerializer(many=True, read_only=True)
    role = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = [
            "id",
            "username",
            "email",
            "first_name",
            "last_name",
            "groups",
            "role",
            "is_active",
        ]

    def get_role(self, obj):
        """Get the primary role of the user."""
        from .permissions import get_user_role

        return get_user_role(obj)


class UserRegistrationSerializer(serializers.ModelSerializer):
    password = serializers.CharField(
        write_only=True, required=True, style={"input_type": "password"}
    )
    password2 = serializers.CharField(
        write_only=True, required=True, style={"input_type": "password"}
    )

    class Meta:
        model = User
        fields = [
            "username",
            "email",
            "password",
            "password2",
            "first_name",
            "last_name",
        ]

    def validate(self, attrs):
        if attrs["password"] != attrs["password2"]:
            raise serializers.ValidationError(
                {"password": "Password fields didn't match."}
            )
        return attrs

    def create(self, validated_data):
        # Remove password2 from the data
        validated_data.pop("password2", None)
        password = validated_data.pop("password")

        # Create user with remaining data
        user = User.objects.create(**validated_data)
        user.set_password(password)

        # Add default role (regular user)
        user_group, _ = Group.objects.get_or_create(name=settings.USER_ROLES["USER"])
        user.groups.add(user_group)

        user.save()
        return user


class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(
        required=True, write_only=True, style={"input_type": "password"}
    )
    new_password = serializers.CharField(
        required=True, write_only=True, style={"input_type": "password"}
    )
    new_password2 = serializers.CharField(
        required=True, write_only=True, style={"input_type": "password"}
    )

    def validate(self, attrs):
        if attrs["new_password"] != attrs["new_password2"]:
            raise serializers.ValidationError(
                {"new_password": "Password fields didn't match."}
            )
        return attrs


class UserUpdateSerializer(serializers.ModelSerializer):
    role = serializers.CharField(write_only=True, required=False)

    class Meta:
        model = User
        fields = ["username", "email", "first_name", "last_name", "is_active", "role"]

    def update(self, instance, validated_data):
        # Handle role update if provided (admin only)
        role = validated_data.pop("role", None)

        # Update user fields
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()

        # Update role if provided
        if role and role in settings.USER_ROLES.values():
            # Clear existing role groups
            for group in instance.groups.all():
                if group.name in settings.USER_ROLES.values():
                    instance.groups.remove(group)

            # Add new role group
            role_group, _ = Group.objects.get_or_create(name=role)
            instance.groups.add(role_group)

        return instance
