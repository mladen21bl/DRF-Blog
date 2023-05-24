from django.urls import path, include
from django.conf.urls import url
from rest_framework.routers import DefaultRouter
from djoser import views as djoser_views
from . import views
from .views import IndexView, PasswordResetDoneView, CustomPasswordResetView, UserCreate, ForbiddenView, logout_view, CheckView, UserRegistrationView, UserListView, SimpleListView, UserDetailView, UserDeleteView, ActivateAccountView, login_view, profile_view
from django.contrib.auth import views as auth_views


router = DefaultRouter()
router.register('users', djoser_views.UserViewSet, basename='user')

app_name = 'MyApp'

urlpatterns = [
    path('', IndexView.as_view(), name='indexview'),
    path('forbidden/', ForbiddenView.as_view(), name='forbiddenview'),
    path('verify-ip-address/<str:token>/', views.verify_ip_address, name='verifyipaddress'),
    path('check/', CheckView.as_view(), name='checkview'),
    path('register/', UserRegistrationView.as_view(), name='userregistrationview'),
    path('myregister/', UserCreate.as_view(), name='myregister'),
    path('users/', UserListView.as_view(), name='userlistview'),
    path('simplelistview/', SimpleListView.as_view(), name='simplelistview'),
    path('users/<int:pk>/', UserDetailView.as_view(), name='userdetailview'),
    path('users/<int:pk>/delete/', UserDeleteView.as_view(), name='userdeleteview'),
    path('activate/<str:uid>/<str:token>/', ActivateAccountView.as_view(), name='activateaccountview'),
    path('mypassword/reset/', CustomPasswordResetView.as_view(), name='mypassword_reset'),
    path('password/reset/', auth_views.PasswordResetView.as_view(
        template_name='password_reset.html',
        email_template_name='password_reset_email.html',
        subject_template_name='password_reset_subject.txt'
    ), name='password_reset'),
    path('password/reset/done/', auth_views.PasswordResetCompleteView.as_view(template_name='password_reset_complete.html'), name='password_reset_complete'),
    path('password/password_reset/done/', PasswordResetDoneView.as_view(), name='passwordresetdone'),
    path('login/', login_view, name='loginview'),
    path('logout/', logout_view, name='logoutview'),
    path('profile/', profile_view, name='profileview'),
]
