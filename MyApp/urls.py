from django.urls import path, include
from rest_framework.routers import DefaultRouter
from djoser import views as djoser_views
from . import views
from .views import (
    IndexView,
    send_verification_email,
    verification_failed,
    PostDetailView,
    DeleteKomentarView,
    PostEditView,
    CreateKomentarView,
    PostDeleteView,
    PostCreateView,
    CustomPasswordResetCompleteView,
    verify_ip_address,
    CustomPasswordResetView,
    PasswordResetDoneView,
    send_verification_email,
    logout_view,
    CheckView,
    UserRegistrationView,
    SimpleListView,
    UserDetailView,
    UserDeleteView,
    ActivateAccountView,
    login_view,
    profile_view,
)
from django.contrib.auth import views as auth_views
from django.conf.urls.static import static
from django.conf import settings



router = DefaultRouter()
router.register('users', djoser_views.UserViewSet, basename='user')

app_name = 'MyApp'

urlpatterns = [
    path('', IndexView.as_view(), name='indexview'),

    path('register/', UserRegistrationView.as_view(), name='register'),
    path('simplelistview/', SimpleListView.as_view(), name='simplelistview'),
    path('users/<int:pk>/', UserDetailView.as_view(), name='userdetailview'),
    path('users/<int:pk>/delete/', UserDeleteView.as_view(), name='userdeleteview'),
    path('activate/<str:uid>/<str:token>/', ActivateAccountView.as_view(), name='activateaccountview'),

    path('verify-ip-address/<str:uid>/<str:token>/', verify_ip_address, name='verifyipaddress'),
    path('verification-failed/', views.verification_failed, name='verificationfailed'),
    path('verification-email-sent/', views.VerificationEmailSentView.as_view(), name='verificationemailsent'),
    path('send-verification-email/', send_verification_email, name='sendverificationemail'),
    path('check/', CheckView.as_view(), name='checkview'),

    path('password/reset/', CustomPasswordResetView.as_view(template_name='password_reset_custom.html'), name='password_reset'), #PRVO
    path('password/password_reset/done/', CustomPasswordResetCompleteView.as_view(template_name='password_reset_done.html'), name='password_reset_complete'),#DRUGO
    path('password/reset/done/', CustomPasswordResetCompleteView.as_view(), name='password_reset_complete'),#CETVRTO

    path('post/create/', views.PostCreateView.as_view(), name='post_create'),
    path('post/list/', views.PostListView.as_view(), name='post_list'),
    path('post/<slug:slug>/', views.PostDetailView.as_view(), name='post_detail'),
    path('post/<int:pk>/delete/', views.PostDeleteView.as_view(), name='post_delete'),
    path('post/<slug:slug>/edit/', PostEditView.as_view(), name='post_edit'),
    path('post/<int:post_id>/komentar/create/', CreateKomentarView.as_view(), name='create_komentar'),
    path('post/<int:post_id>/komentar/<int:pk>/delete/', DeleteKomentarView.as_view(), name='delete_komentar'),

    path('accounts/login/', auth_views.LoginView.as_view(template_name='new_login.html'), name='login'),
    path('login/', login_view, name='loginview'),
    path('logout/', logout_view, name='logoutview'),
    path('profile/', profile_view, name='profileview'),
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

urlpatterns += router.urls
