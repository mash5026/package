from django.urls import path
from .views import LoginView, ValidationToken, OTPView, ValidationOTP, DefineTerminal, GetItemOrder

urlpatterns = [
    # Other URL patterns...
    path("authenticate/", LoginView.as_view()),
    path("valid-token/", ValidationToken.as_view()),
    path("User/get-otp/", OTPView.as_view()),
    path("valid-otp/", ValidationOTP.as_view()),
    path("defineTerminal/", DefineTerminal.as_view()),
    path("itemorder/", GetItemOrder.as_view()),
]