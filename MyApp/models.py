from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from django.utils.text import slugify
from django.urls import reverse
from django.contrib.auth.tokens import default_token_generator
from django.views.generic import CreateView, DeleteView, ListView, DetailView
from django.shortcuts import get_object_or_404
from django.urls import reverse_lazy
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.exceptions import PermissionDenied
from django.utils.text import slugify
from django.utils.crypto import get_random_string
import hashlib
import secrets
from PIL import Image
from django.db.models.signals import post_save
from django.dispatch import receiver


salt = secrets.token_hex(16)


class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    USER_TYPE_CHOICES = (
        ('hash_editor', 'Hash Editor'),
        ('has_user', 'Has User'),
    )

    ip_addresses = models.TextField(blank=True)
    user_type = models.CharField(max_length=50, choices=USER_TYPE_CHOICES, default='has_user')

    def add_ip_address(self, ip_address):
        ip_addresses_list = self.ip_addresses.split(',') if self.ip_addresses else []
        if ip_address not in ip_addresses_list:
            ip_addresses_list.append(ip_address)
            self.ip_addresses = ','.join(ip_addresses_list)
            self.save()

    def verify_ip_address(self, token):
        if default_token_generator.check_token(self.user, token):
            return True
        return False

    def add_verified_ip_address(self, ip_address):
        if self.verify_ip_address(ip_address):
            self.add_ip_address(ip_address)
            return True
        return False

    def get_ip_addresses(self):
        return self.ip_addresses.split(',') if self.ip_addresses else []

    def __str__(self):
        return self.user.username


@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    if created and instance.is_superuser:
        UserProfile.objects.create(user=instance, user_type='hash_editor')
    elif created:
        UserProfile.objects.create(user=instance, user_type='has_user')

@receiver(post_save, sender=User)
def save_user_profile(sender, instance, **kwargs):
    if instance.is_superuser:
        instance.userprofile.save()


class Komentar(models.Model):
    post = models.ForeignKey('Post', related_name='komentari', on_delete=models.CASCADE)
    text = models.TextField()
    author = models.ForeignKey(UserProfile, on_delete=models.CASCADE)

    def __str__(self):
        return self.text



class Post(models.Model):
    CATEGORY_CHOICES = (
        ('politika', 'Politika'),
        ('sport', 'Sport'),
        ('ekonomija', 'Ekonomija'),
        ('umjetnost', 'Umjetnost'),
        ('astrologija', 'Astrologija'),
        ('moda', 'Moda'),
    )

    author = models.ForeignKey(UserProfile, on_delete=models.CASCADE)
    title = models.CharField(max_length=200)
    category = models.CharField(max_length=100, choices=CATEGORY_CHOICES)
    text = models.TextField()
    image = models.ImageField(upload_to='post_images')
    created_date = models.DateTimeField(default=timezone.now)
    slug = models.SlugField(max_length=255, unique=True, blank=True)
    category_slug = models.SlugField(max_length=255, unique=True, blank=True)

    def save(self, *args, **kwargs):
        if not self.slug:
            salt = secrets.token_hex(16)
            hashed_id = hashlib.sha256((str(self.id) + salt).encode()).hexdigest()
            self.slug = hashed_id

        if not self.category_slug:
            salt = secrets.token_hex(16)
            hashed_id = hashlib.sha256((str(self.category) + salt).encode()).hexdigest()
            self.category_slug = hashed_id

        super().save(*args, **kwargs)

    def get_absolute_url(self):
        return reverse('MyApp:post_list')

    def __str__(self):
        return self.title
