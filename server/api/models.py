from django.db import models
from django.db.models.signals import pre_save
from django.dispatch import receiver
from django.contrib.auth.hashers import make_password
from django.contrib.auth.models import User

class Site(models.Model):
	ip = models.GenericIPAddressField(blank=False, null=False)
	description = models.TextField(blank=True, null=True)
	key = models.CharField(max_length=100, blank=False, null=False)
	active = models.BooleanField(default=True)

	def __str__(self):
		return self.ip

class SiteAccount(models.Model):
	user = models.ForeignKey(User, on_delete=models.CASCADE, blank=False, null=False)
	site = models.ForeignKey(Site, related_name='accounts', on_delete=models.CASCADE, blank=False, null=False)

	def __str__(self):
		return self.user.username