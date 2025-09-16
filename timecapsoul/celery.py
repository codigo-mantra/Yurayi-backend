import os
from celery import Celery
from celery.schedules import crontab


os.environ.setdefault("DJANGO_SETTINGS_MODULE", "timecapsoul.settings")

app = Celery("timecapsoul")

app.config_from_object("django.conf:settings", namespace="CELERY")

# autodiscovers tasks.py in all INSTALLED_APPS
app.autodiscover_tasks()

# ⏰ Celery Beat schedule
app.conf.beat_schedule = {
    'run-capsoul-notifications-every-hour': {
        'task': 'memory_room.tasks.notification.capsoul_notification_handler',  
        'schedule': crontab(minute=0),  # every hour, at 00 minutes
    },
}