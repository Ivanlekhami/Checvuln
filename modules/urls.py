from django.urls import path
from .views import *

urlpatterns = [
    path("", home, name="home"),
    path("register/", register, name="register"),
    path("sign_in/", sign_in, name="sign_in"),
    path("logout/", logOut, name="logout"),
    path('verify/', verify, name='verify'),
]