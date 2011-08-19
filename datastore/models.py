from django.db import models
from django.contrib.auth.models import User

class UserProfile(models.Model):
	userID = models.ForeignKey(User, related_name='userID', unique=True)
	#isGroup = models.BooleanField()
	#groupOwner = models.ForeignKey(User, related_name='groupOwner', null=True, blank=True)
	#privAPIKey = models.TextField()
	#pubAPIKey = models.TextField()
	apiKey = models.TextField()

	def __unicode__(self):      
		return "%s's Profile" % self.userID.username

