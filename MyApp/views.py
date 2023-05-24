from django.shortcuts import redirect, get_object_or_404, render
from django.views.generic import TemplateView, ListView, DetailView, DeleteView, UpdateView, CreateView
from djoser import views as djoser_views
from .serializers import UserRegistrationSerializer
from rest_framework import generics
from django.contrib.auth.models import User
from .serializers import UserRegistrationSerializer
from django.shortcuts import get_object_or_404
from django.utils.http import urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_text
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth import get_user_model
from django.urls import reverse, reverse_lazy
from django.http import HttpResponseRedirect
from django.shortcuts import redirect, render
from django.contrib.auth import authenticate, login
from django.contrib.auth.decorators import login_required
from django.contrib.auth import logout
from django.contrib.auth.hashers import make_password
from django.shortcuts import redirect
from rest_framework import generics
from .serializers import UserRegistrationSerializer
from .models import UserProfile
from django.shortcuts import get_object_or_404
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from .models import UserProfile
from django.contrib.auth.models import User
from django.contrib.auth.tokens import default_token_generator
from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import send_mail
from django.shortcuts import redirect
from django.urls import reverse_lazy
from django.views.generic import CreateView
from .models import User, UserProfile
from django.contrib.auth.tokens import default_token_generator
from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import send_mail
from django.shortcuts import redirect
from django.urls import reverse_lazy
from django.views.generic import CreateView
from .models import User, UserProfile
from django.utils.http import urlsafe_base64_encode
from django.conf import settings
from django.contrib.auth.views import PasswordResetView



class CustomPasswordResetView(PasswordResetView):
    template_name = 'custom_password_reset.html'
    email_template_name = 'custom_password_reset_email.html'
    subject_template_name = 'custom_password_reset_subject.txt'

    def send_verification_email(self, user):
        token = default_token_generator.make_token(user)
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        current_site = self.request.get_host()
        verification_url = reverse('MyApp:password_reset_confirm', kwargs={'uidb64': uid, 'token': token})
        verification_link = f"{current_site}{verification_url}"

        # Render the email template with the verification URL
        email_context = {
            'password_reset_url': verification_link,
        }
        email_body = render_to_string(self.email_template_name, email_context)

        # Send the verification email
        subject = 'Reset Your Password'
        from_email = settings.DEFAULT_FROM_EMAIL
        to_email = user.email

        send_mail(subject, email_body, from_email, [to_email])

        # Redirect the user to a success page or appropriate view
        return redirect('MyApp:verificationemailsent')


class IndexView(TemplateView):
    template_name = 'base.html'

class ForbiddenView(TemplateView):
    template_name = 'forbidden.html'

class PasswordResetDoneView(TemplateView):
    template_name = 'password_sent.html'

class CheckView(TemplateView):
    template_name = 'check.html'

class UserCreate(CreateView):
    model = User
    template_name = 'moj.html'
    fields = ('email', 'username', 'password')

    def form_valid(self, form):
        # Kreiranje instance User objekta
        user = form.save(commit=False)
        user.is_active = False  # Postavljanje računa na neaktivan dok se ne potvrdi e-pošta
        user.save()

        # Kreiranje instance UserProfile objekta
        profile = UserProfile(user=user)
        profile.save()

        # Slanje verifikacijskog e-maila
        self.send_verification_email(user)

        return redirect('MyApp:checkview')

    def send_verification_email(self, user):
        token = default_token_generator.make_token(user)
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        current_site = get_current_site(self.request)
        verification_url = reverse_lazy('MyApp:activateaccountview', kwargs={'uid': uid, 'token': token})
        verification_link = f"{current_site}{verification_url}"
        subject = 'Verify Your Account'
        message = f'Please verify your account by clicking the following link:\n\n{verification_link}'
        send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [user.email])

class UserRegistrationView(generics.CreateAPIView):
    serializer_class = UserRegistrationSerializer
    template_name = 'registration.html'

    def get_serializer_context(self):
        context = super().get_serializer_context()
        context['ip_address'] = self.request.META.get('HTTP_X_REAL_IP') or self.request.META.get('REMOTE_ADDR')
        return context

    def post(self, request, *args, **kwargs):
        response = super().post(request, *args, **kwargs)
        return redirect('MyApp:checkview')

class UserListView(generics.ListAPIView):
    queryset = User.objects.all()
    serializer_class = UserRegistrationSerializer

class SimpleListView(ListView):
    queryset = User.objects.all()
    context_object_name = 'korisnici'
    template_name = 'simple_list.html'

class UserDetailView(DetailView):
    model = User
    context_object_name = 'user'
    template_name = 'user_detail.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        user = self.get_object()
        profile = get_object_or_404(UserProfile, user=user)
        ip_addresses = profile.get_ip_addresses()  # koristi metodu get_ip_addresses() umjesto split(',') kako bi dobili listu IP adresa
        current_ip = self.request.META['REMOTE_ADDR']  # dobivanje trenutne IP adrese korisnika
        context['ip_addresses'] = ip_addresses
        context['current_ip'] = current_ip
        return context

class UserDeleteView(DeleteView):
    model = User
    template_name = 'user_delete.html'
    success_url = reverse_lazy('MyApp:simplelistview')


class ActivateAccountView(TemplateView):
    template_name = 'account_activation.html'

    def get(self, request, uid, token):
        User = get_user_model()
        try:
            uid = force_text(urlsafe_base64_decode(uid))
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            user = None

        if user is not None and default_token_generator.check_token(user, token):
            user.is_active = True
            user.save()
            return redirect('MyApp:loginview')
        else:
            return redirect('MyApp:indexview')

#######################################################

def send_verification_email(request):
    user = request.user
    ip_address = request.META.get('REMOTE_ADDR')

    # Generate a verification token for the IP address
    token = default_token_generator.make_token(user)

    # Construct the verification link
    verification_link = reverse('MyApp:verifyipaddress', kwargs={'token': token})
    verification_url = request.build_absolute_uri(verification_link)

    # Send the verification email
    subject = 'IP Address Verification'
    message = f'Please verify your new IP address ({ip_address}) by clicking the following link:\n\n{verification_url}'
    from_email = settings.DEFAULT_FROM_EMAIL
    to_email = user.email

    send_mail(subject, message, from_email, [to_email])

    # Redirect the user to a success page or appropriate view
    return redirect('MyApp:verificationemailsent')

def verify_ip_address(request, token):
    user = request.user
    ip_address = request.META.get('REMOTE_ADDR')

    # Check if the token is valid and associated with the user
    if default_token_generator.check_token(user, token):
        # Add the new IP address to the user's list
        user_profile = get_object_or_404(UserProfile, user=user)
        user_profile.add_ip_address(ip_address)

        # Redirect the user to the login page or appropriate view
        return redirect('MyApp:loginview')
    else:
        # Handle the case when the token is invalid
        return redirect('MyApp:verificationfailed')


@login_required
def profile_view(request):
    return render(request, 'profile.html')

def login_view(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request, username=username, password=password)

        if user is not None:
            # Check if the user's IP address is in their IP addresses list
            ip_address = request.META.get('REMOTE_ADDR')
            user_profile = get_object_or_404(UserProfile, user=user)
            ip_addresses = user_profile.ip_addresses.split(',') if user_profile.ip_addresses else []

            if ip_address not in ip_addresses:
                # Redirect the user to the email verification page
                return redirect('MyApp:sendverificationemail')

            # Continue with the authentication process
            login(request, user)
            return redirect('MyApp:profileview')
        else:
            return render(request, 'login.html', {'error': 'Invalid username or password'})
    else:
        return render(request, 'login.html')

def logout_view(request):
    logout(request)
    return redirect('MyApp:indexview')
