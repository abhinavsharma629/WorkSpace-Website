from django.contrib import admin
from django.urls import path, include
from django.contrib.auth.views import LoginView, LogoutView

urlpatterns = [
    path('admin/', admin.site.urls),
    path('test/', include('testPro.urls')),
    path('',LoginView.as_view(template_name="testPro/signin.html"), name="login"),
    path('logout',LogoutView.as_view(), name="logout"),
]
