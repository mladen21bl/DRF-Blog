from django.shortcuts import redirect, get_object_or_404, render
from django.views.generic import TemplateView, ListView, DetailView, DeleteView, CreateView, UpdateView
from djoser import views as djoser_views
from .serializers import UserRegistrationSerializer, PostSerializer
from rest_framework import generics
from django.contrib.auth import get_user_model, authenticate, login, logout
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.utils.encoding import force_bytes, force_str
from django.urls import reverse, reverse_lazy
from django.core.mail import send_mail
from django.conf import settings
from django.contrib.auth.decorators import login_required
from .models import UserProfile, Post, Komentar
from django.template.loader import render_to_string
from django.contrib.auth import views as auth_views
from django.contrib.auth.views import PasswordResetCompleteView
from django.contrib import messages
from MyApp import models
from django.core.paginator import Paginator, PageNotAnInteger, EmptyPage
from django.db.models import Q
from django.contrib.auth.mixins import LoginRequiredMixin, UserPassesTestMixin
from django.core.exceptions import PermissionDenied
from django.http import HttpResponseRedirect, HttpResponseForbidden
from django.views.generic.detail import SingleObjectMixin
import json
from django.core.paginator import Paginator


class CustomPasswordResetCompleteView(PasswordResetCompleteView):
    template_name = 'password_reset_complete.html'


class CustomPasswordResetView(auth_views.PasswordResetView):
    template_name = 'password_reset_custom.html'
    email_template_name = 'password_reset_email.html'
    subject_template_name = 'password_reset_subject.txt'
    success_url = reverse_lazy('password_reset_done')


class IndexView(TemplateView):
    template_name = 'base.html'


class PasswordResetDoneView(TemplateView):
    template_name = 'password_sent.html'

class VerificationEmailSentView(TemplateView):
    template_name = 'verification_email_sent.html'

class CheckView(TemplateView):
    template_name = 'check.html'


class UserRegistrationView(generics.CreateAPIView):
    serializer_class = UserRegistrationSerializer

    def get_serializer_context(self):
        context = super().get_serializer_context()
        context['ip_address'] = self.request.META.get('HTTP_X_REAL_IP') or self.request.META.get('REMOTE_ADDR')
        return context

    def post(self, request, *args, **kwargs):
        response = super().post(request, *args, **kwargs)
        return redirect('MyApp:checkview')



class SimpleListView(ListView):
    queryset = get_user_model().objects.all()
    context_object_name = 'korisnici'
    template_name = 'simple_list.html'


class UserDetailView(DetailView):
    model = get_user_model()
    context_object_name = 'user'
    template_name = 'user_detail.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        user = self.get_object()
        profile = get_object_or_404(UserProfile, user=user)
        ip_addresses = profile.get_ip_addresses()
        current_ip = self.request.META['REMOTE_ADDR']
        context['ip_addresses'] = ip_addresses
        context['current_ip'] = current_ip
        return context


def verification_failed(request):
    return render(request, 'verification_failed.html')

class UserDeleteView(DeleteView):
    model = get_user_model()
    template_name = 'user_delete.html'
    success_url = reverse_lazy('MyApp:indexview')


class ActivateAccountView(TemplateView):
    template_name = 'account_activation.html'

    def get(self, request, uid, token):
        User = get_user_model()
        try:
            uid = force_str(urlsafe_base64_decode(uid))
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            user = None

        if user is not None and default_token_generator.check_token(user, token):
            user.is_active = True
            user.save()
            return redirect('MyApp:loginview')
        else:
            return redirect('MyApp:indexview')

def send_verification_email(request, user, ip_address):
    # Generate a verification token for the IP address
    token = default_token_generator.make_token(user)
    uid = urlsafe_base64_encode(force_bytes(user.pk))

    # Construct the verification link
    verification_link = reverse('MyApp:verifyipaddress', kwargs={'uid': uid, 'token': token})
    verification_url = request.build_absolute_uri(verification_link)

    # Generate the context for the email template
    context = {
        'user': user,
        'verification_link': verification_url,
        'uid': uid,
    }

    # Render the email template with the given context
    email_body = render_to_string('email/ip_verification.html', context)

    # Send the verification email
    subject = 'IP Address Verification'
    from_email = settings.DEFAULT_FROM_EMAIL
    to_email = user.email

    send_mail(subject, email_body, from_email, [to_email])

    # Redirect the user to a success page or appropriate view
    return redirect('MyApp:verificationemailsent')


def verify_ip_address(request, uid, token):
    User = get_user_model()
    try:
        # Dekodiraj UID iz baze64 reprezentacije
        uid = force_str(urlsafe_base64_decode(uid))
        # Pronađi korisnika na osnovu dekodiranog UID-a
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    if user is not None and default_token_generator.check_token(user, token):
        ip_address = request.META.get('REMOTE_ADDR')
        # Dodaj novu IP adresu u listu verifikovanih IP adresa korisnika
        user_profile = UserProfile.objects.get(user=user)
        user_profile.add_ip_address(ip_address)
        # Sačuvaj promene
        user_profile.save()
        # Nastavi sa procesom autentifikacije
        login(request, user)
        # Preusmeri korisnika na prikaz profila
        return redirect('MyApp:profileview')
    else:
        # Obradi slučaj kada je token nevažeći
        return redirect('MyApp:verificationfailed')


@login_required
def profile_view(request):
    return render(request, 'profile.html')


def login_view(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        user = authenticate(request, username=username, password=password)

        if user is not None and user.is_active:
            ip_address = request.META.get('REMOTE_ADDR')
            user_profile = get_object_or_404(UserProfile, user=user)
            ip_addresses = user_profile.get_ip_addresses()

            if ip_address in ip_addresses:
                # User's IP address is already verified, proceed with login
                login(request, user)
                return redirect('MyApp:profileview')
            else:
                # Send verification email and redirect to verification email sent page
                return send_verification_email(request, user, ip_address)
        else:
            # Wrong credentials, display error message
            messages.error(request, 'Pogrešni podaci.')

    return render(request, 'login.html')

def logout_view(request):
    logout(request)
    return redirect('MyApp:indexview')
##############################################POST###################################


class PostCreateView(CreateView):
    model = Post
    fields = ['title', 'category', 'text', 'image']
    template_name = 'post_create.html'
    success_url = reverse_lazy('MyApp:post_list')

    def form_valid(self, form):
        form.instance.author = self.request.user.userprofile

        # Obrada i spremanje slike
        image = form.cleaned_data.get('image')
        if image:
            # Postoji odabrana slika
            form.instance.image = image

        response = super().form_valid(form)

        # Stvaranje JSON datoteke
        post = form.instance
        PostSerializer.save_as_json(post)

        return response


class PostEditView(LoginRequiredMixin, UserPassesTestMixin, UpdateView):
    model = Post
    fields = ['title', 'category', 'text', 'image']
    template_name = 'post_edit.html'
    success_url = reverse_lazy('MyApp:post_list')

    def form_valid(self, form):
        form.instance.author = self.request.user.userprofile

        # Obrada i spremanje slike
        image = form.cleaned_data.get('image')
        if image:
            # Postoji odabrana slika
            form.instance.image = image

        return super().form_valid(form)

    def get_object(self, queryset=None):
        slug = self.kwargs.get('slug')
        return get_object_or_404(Post, slug=slug)

    def test_func(self):
        obj = self.get_object()
        if obj.author.user != self.request.user and not self.request.user.is_superuser:
            raise PermissionDenied("Niste ovlašteni za uređivanje ovog posta.")
        return True


class PostDeleteView(UserPassesTestMixin, DeleteView):
    model = Post
    template_name = 'post_delete.html'
    success_url = reverse_lazy('MyApp:post_list')

    def test_func(self):
        obj = self.get_object()
        return obj.author.user == self.request.user or self.request.user.is_superuser


class PostListView(ListView):
    model = Post
    template_name = 'post_list.html'
    context_object_name = 'posts'
    paginate_by = 1

    def get_queryset(self):
        queryset = super().get_queryset()

        category = self.request.GET.get('category')
        search = self.request.GET.get('search')

        if category:
            queryset = queryset.filter(category=category)

        if search:
            queryset = queryset.filter(title__icontains=search)

        return queryset

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        post_list = self.get_queryset()

        per_page = self.request.GET.get('per_page')  # Dobivanje vrijednosti per_page parametra
        paginator = Paginator(post_list, per_page) if per_page else Paginator(post_list, self.paginate_by)

        page = self.request.GET.get('page')
        try:
            posts = paginator.page(page)
        except PageNotAnInteger:
            posts = paginator.page(1)
        except EmptyPage:
            posts = paginator.page(paginator.num_pages)

        context['page_obj'] = posts
        return context


class PostDetailView(DetailView):
    model = Post
    template_name = 'post_detail.html'
    context_object_name = 'post'


#####################################COMMENT###############################


class CreateKomentarView(CreateView):
    model = Komentar
    fields = ['text']
    context_object_name = "komentari"
    template_name = 'create_komentar.html'
    http_method_names = ['get', 'post']

    def get_success_url(self):
        return reverse('MyApp:post_detail', kwargs={'pk': self.object.post.pk})

    def form_valid(self, form):
        form.instance.author = self.request.user.userprofile
        form.instance.post_id = self.kwargs['post_id']
        return super().form_valid(form)

class DeleteKomentarView(LoginRequiredMixin, UserPassesTestMixin, DeleteView):
    model = Komentar
    template_name = 'delete_komentar.html'
    http_method_names = ['post']

    def get_success_url(self):
        return reverse('MyApp:post_detail', kwargs={'pk': self.object.post.pk})


    def test_func(self):
        komentar = self.get_object()
        user = self.request.user
        return user.is_superuser or komentar.author.user == user

    def delete(self, request, *args, **kwargs):
        self.object = self.get_object()

        # Check if the user is authorized to delete the comment
        if not self.test_func():
            return HttpResponseForbidden("You are not allowed to delete this comment.")

        # Delete the comment
        self.object.delete()

        # Redirect to the success URL after deletion
        return HttpResponseRedirect(self.get_success_url())
