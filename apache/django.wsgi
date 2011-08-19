import os, sys

apache_configuration= os.path.dirname(__file__)
project = os.path.dirname(apache_configuration)
workspace = os.path.dirname(project)
sys.path.append(workspace) 

sys.path.append('/usr/local/lib/python2.6/dist-packages/django/')
sys.path.append('/home/haksoo/django-projects/sensorsafe/')

os.environ['DJANGO_SETTINGS_MODULE'] = 'sensorsafe.settings'
os.environ['HOME'] = "/home/haksoo/django-projects/private/"
import django.core.handlers.wsgi
application = django.core.handlers.wsgi.WSGIHandler()
