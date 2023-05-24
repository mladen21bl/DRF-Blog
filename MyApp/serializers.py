from django.contrib.auth.models import User
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_text
from django.template.loader import render_to_string
from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import EmailMessage
from djoser.serializers import UserCreateSerializer
from rest_framework import serializers
from django.conf import settings
from django.urls import reverse
from MyApp.models import UserProfile
from djoser.email import ActivationEmail


class UserRegistrationSerializer(UserCreateSerializer):
    ip_address = serializers.IPAddressField(read_only=True)

    class Meta(UserCreateSerializer.Meta):
        model = User
        fields = ('email', 'username', 'password', 'ip_address')

    def send_activation_email(self, user):
        current_site = get_current_site(self.context['request'])
        mail_subject = 'Activate your account'
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = default_token_generator.make_token(user)
        activation_link = reverse('MyApp:activateaccountview', kwargs={'uid': uid, 'token': token})
        activation_url = f"http://{current_site.domain}{activation_link}"

        # Get the user's IP address
        ip_address = self.context['request'].META.get('REMOTE_ADDR')

        # Generate a verification token for the IP address
        ip_token = default_token_generator.make_token(user)

        # Construct the IP verification link
        ip_verification_link = reverse('MyApp:verifyipaddress', kwargs={'token': ip_token})
        ip_verification_url = f"http://{current_site.domain}{ip_verification_link}"

        message = render_to_string(
            'email/activation.html',
            {
                'user': user,
                'activation_link': activation_url,
                'ip_verification_link': ip_verification_url,
                'ip_address': ip_address,
            }
        )

        to_email = user.email
        email = EmailMessage(mail_subject, message, to=[to_email])
        email.send()

    def create(self, validated_data):
        user = super().create(validated_data)
        ip_address = self.context['request'].META.get('REMOTE_ADDR')
        user_profile = UserProfile.objects.get_or_create(user=user)[0]
        user_profile.add_ip_address(ip_address)
        self.send_activation_email(user)
        return user


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email']
