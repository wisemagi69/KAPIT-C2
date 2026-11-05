import os

from django.core.wsgi import get_wsgi_application

os.environ["DJANGO_SETTINGS_MODULE"] = "config.settings"
application = get_wsgi_application()
from .hosted_preflight import enforce_hosted_preflight
enforce_hosted_preflight()
