from django.conf.urls.defaults import *
from django.conf import settings

# Uncomment the next two lines to enable the admin:
from django.contrib import admin
admin.autodiscover()

urlpatterns = patterns('',
	(r'^$', 'django.contrib.auth.views.login'),

	(r'^admin/', include(admin.site.urls)),
	(r'^files/(?P<path>.*)$', 'django.views.static.serve', {'document_root': settings.STATIC_DOC_ROOT}),
	(r'^login/$', 'django.contrib.auth.views.login'),
	(r'^login$', 'django.contrib.auth.views.login'),
	(r'^register/$', 'datastore.views.register'),
	(r'^register$', 'datastore.views.register'),
	(r'^profile/$', 'datastore.views.profile'),
	(r'^profile$', 'datastore.views.profile'),
	(r'^logout/$', 'datastore.views.logout_view'),
	(r'^logout$', 'datastore.views.logout_view'),
	
	(r'^upload/$', 'datastore.views.upload'),
	(r'^upload$', 'datastore.views.upload'),
	
	(r'^query/$', 'datastore.views.query'),
	(r'^query$', 'datastore.views.query'),

	(r'^status/$', 'datastore.views.status'),
	(r'^status$', 'datastore.views.status'),
	
	(r'^display/$', 'datastore.views.display'),
	(r'^display$', 'datastore.views.display'),

	(r'^uploadrules/$', 'datastore.views.uploadrules'),
	(r'^uploadrules$', 'datastore.views.uploadrules'),
	
	(r'^deleterules/$', 'datastore.views.deleterules'),
	(r'^deleterules$', 'datastore.views.deleterules'),
	
	(r'^getrules/$', 'datastore.views.getrules'),
	(r'^getrules$', 'datastore.views.getrules'),
	
	#(r'^datastore/', include('datastore.urls')),

	(r'privacyrules/$', 'datastore.views.privacyrules'),
	(r'privacyrules$', 'datastore.views.privacyrules'),
	
	(r'locationlabel/$', 'datastore.views.locationlabel'),
	(r'locationlabel$', 'datastore.views.locationlabel'),

	(r'search_rules/$', 'datastore.views.search_rules'),
	(r'search_rules$', 'datastore.views.search_rules'),
	
	(r'test/$', 'datastore.views.test'),
	(r'test$', 'datastore.views.test'),
)

