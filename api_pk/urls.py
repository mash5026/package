from django.urls import path
from .views import LoginView, ValidationToken, OTPView, ValidationOTP, DefineTerminal, Estelam, GetItemOrder, ReverseProcessAPIView, ConfirmTransaction, Estelam_100, ORDER_200_CODE, REVERSE_420_CODE_ORDER,CONFIRM_220_CODE_ORDER

urlpatterns = [
    # Other URL patterns...
    path("authenticate/", LoginView.as_view()),
    path("valid-token/", ValidationToken.as_view()),
    path("User/get-otp/", OTPView.as_view()),
    path("valid-otp/", ValidationOTP.as_view()),
    path("defineTerminal/", DefineTerminal.as_view()),
    path("estelam/", Estelam.as_view()),
    path("itemorder/", GetItemOrder.as_view()),
    path("confirm/", ConfirmTransaction.as_view()),
    path('reverse-process/', ReverseProcessAPIView.as_view()),
    path("estelamtrans/", Estelam_100.as_view()),
    path("itemordertrans/", ORDER_200_CODE.as_view()),
    path("reversetrans/", REVERSE_420_CODE_ORDER.as_view()),
    path("confirmtrans/", CONFIRM_220_CODE_ORDER.as_view()),
]