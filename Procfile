web: gunicorn --bind :8000 timecapsoul.wsgi:application
worker: celery -A timecapsoul worker --loglevel=info --concurrency=4
beat: celery -A timecapsoul beat -l info -S django