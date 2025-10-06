import os
from celery import Celery
from datetime import timedelta

from celery.schedules import crontab


os.environ.setdefault("DJANGO_SETTINGS_MODULE", "timecapsoul.settings")

app = Celery("timecapsoul")

app.config_from_object("django.conf:settings", namespace="CELERY")

# autodiscovers tasks.py in all INSTALLED_APPS
app.autodiscover_tasks()

# # ⏰ Celery Beat schedule
# app.conf.beat_schedule = {
#     'run-capsoul-notifications-every-hour': {
#         'task': 'memory_room.tasks.notification.capsoul_notification_handler',  
#         'schedule': crontab(minute=0),  # every hour, at 00 minutes
#     },
# }

# ⏰ Celery Beat schedule
app.conf.beat_schedule = {
    # 'test-task-minutes': {
    #     'task': 'memory_room.tasks.send_report',  
    #     'schedule': timedelta(seconds=30),  # every hour, at 00 minutes
    # },
    
    'test-task-minutes-scheduler': {
        'task': 'memory_room.tasks.capsoul_notification_handler',  
        'schedule': timedelta(seconds=60*60),  # every hour, at 60 minutes
    },
    "clear-cache-every-3-hours": {
        "task": "memory_room.tasks.clear_all_cache",
        "schedule": crontab(minute=0, hour="*/1"),  # every 3 hours
    },
}