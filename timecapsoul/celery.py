import os
from celery import Celery

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "timecapsoul.settings")

app = Celery("timecapsoul")

app.config_from_object("django.conf:settings", namespace="CELERY")

# autodiscovers tasks.py in all INSTALLED_APPS
app.autodiscover_tasks()
