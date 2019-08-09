from django.db import models

class Tokens(models.Model):
    username=models.CharField(max_length=100)
    access_token=models.CharField(max_length=1000)
    refresh_token=models.CharField(max_length=1000)
