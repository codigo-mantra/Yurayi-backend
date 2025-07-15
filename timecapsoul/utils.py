import os
from storages.backends.s3boto3 import S3Boto3Storage

class MediaRootS3Boto3Storage(S3Boto3Storage):
    location = 'media'  

def load_env(path='.env'):
    if os.path.exists(path):
        with open(path) as f:
            for line in f:
                if line.strip() and not line.startswith('#'):
                    key, val = line.strip().split('=', 1)
                    os.environ[key] = val