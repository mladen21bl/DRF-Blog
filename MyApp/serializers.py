from django.contrib.auth.models import User
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.template.loader import render_to_string
from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import EmailMessage
from djoser.serializers import UserCreateSerializer
from django.core.serializers import serialize
from rest_framework import serializers
from django.conf import settings
from django.urls import reverse
from MyApp.models import UserProfile
from djoser.email import ActivationEmail
import json
import os

class UserRegistrationSerializer(UserCreateSerializer):
    ip_address = serializers.IPAddressField(read_only=True)

    class Meta(UserCreateSerializer.Meta):
        model = User
        fields = ('email', 'username', 'password', 'ip_address')

    def send_activation_email(self, user):
        current_site = get_current_site(self.context['request'])
        mail_subject = 'Aktivirajte svoj profil'
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = default_token_generator.make_token(user)
        activation_link = reverse('MyApp:activateaccountview', kwargs={'uid': uid, 'token': token})
        activation_url = f"http://{current_site.domain}{activation_link}"
        message = render_to_string(
            'email/activation.html',
            {
                'user': user,
                'activation_link': activation_url,
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


class PostSerializer:
    @staticmethod
    def serialize(post):
        post_data = serialize('json', [post])
        data = json.loads(post_data)[0]['fields']
        data['author'] = post.author.user.username  # Pristup korisničkom imenu autora
        return json.dumps(data)

    @staticmethod
    def save_as_json(post):
        data = PostSerializer.serialize(post)
        file_name = f"{post.slug}.json"
        file_path = os.path.join(settings.JSON_FILE_DIRECTORY, file_name)  # Dodajte ovu liniju

        with open(file_path, 'w') as file:
            file.write(data)
