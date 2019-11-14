from django.contrib import admin
from django.urls import path, include
from . import views
urlpatterns = [
    path('profile', views.profile, name="profile"),
    path('signup', views.signup, name="signup"),
    path('saveToken', views.saveToken, name="saveToken"),
    path('network', views.network, name="network"),
    path('network1', views.network1, name="network1"),
    path('clouds', views.clouds, name="clouds"),
    path('login', views.login, name="login"),
    path('login1', views.login1, name="login1"),
    path('complete/google-oauth2/', views.gd_oauth2, name="gd_oauth2"),
    path('complete/dropbox-oauth2', views.drop_oauth2, name="drop_oauth2"),
    path('dropboxLogin', views.dropboxLogin, name="dropboxLogin"),
    path('personal', views.personal, name="personal"),
    path('github', views.github, name="github"),
    path('complete/gitHub-oauth2', views.git_complete, name="git_complete"),
    path('gitHubLogin', views.gitHubLogin, name="gitHubLogin"),
    path('showNote/<id>', views.showNote, name="showNote"),
    path('showGitHub/<id>', views.showGitHub, name="showGitHub"),
    path('signUpInCurrentServer/', views.signUpInCurrentServer, name="signUpInCurrentServer"),
]
