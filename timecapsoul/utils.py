import os
from storages.backends.s3boto3 import S3Boto3Storage
import boto3
import mimetypes
import boto3
from django.conf import settings



class MediaRootS3Boto3Storage(S3Boto3Storage):
    location = 'media'  
    file_overwrite = False
    default_acl = 'private'


def upload_to_s3(file_path, s3_key=None):
    s3 = boto3.client(
        's3',
        aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
        aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
        region_name=settings.AWS_S3_REGION_NAME
    )

    if not s3_key:
        s3_key = f'media/{os.path.basename(file_path)}'

    content_type, _ = mimetypes.guess_type(file_path)
    content_type = content_type or 'application/octet-stream'  # fallback

    with open(file_path, 'rb') as file_data:
        s3.upload_fileobj(
            file_data,
            settings.AWS_STORAGE_BUCKET_NAME,
            s3_key,
            ExtraArgs={
                'ContentType': content_type,
                'ACL': 'public-read'
            }
        )
    return f"https://{settings.AWS_STORAGE_BUCKET_NAME}.s3.{settings.AWS_S3_REGION_NAME}.amazonaws.com/{s3_key}"

def load_env(path='.env'):
    if os.path.exists(path):
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    if '=' in line:
                        key, val = line.split('=', 1)
                        os.environ[key] = val
                    else:
                        print(f"Warning: Skipping invalid .env line: {line}")



def upload_to_s3(file_path):
    """Upload file to S3 and return the S3 URL"""
    try:
        s3_client = boto3.client(
            's3',
            aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
            region_name=settings.AWS_S3_REGION_NAME
        )
        bucket_name = settings.AWS_STORAGE_BUCKET_NAME
        file_name = os.path.basename(file_path)
        with open(file_path, "rb") as file_obj:
            s3_client.upload_fileobj(file_obj, bucket_name, file_name)
        s3_url = f"https://{bucket_name}.s3.{settings.AWS_S3_REGION_NAME}.amazonaws.com/{file_name}"
        print(f"File uploaded to S3: {s3_url}")
        return s3_url
    except Exception as e:
        print(f"Error uploading to S3: {e}")
        return None

def upload_to_file_s3_bucket():
    try:
        s3_client = boto3.client(
            's3',
            aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
            region_name=settings.AWS_S3_REGION_NAME
        )
        bucket_name = settings.AWS_STORAGE_BUCKET_NAME
    except:
        pass


import boto3
import json
import os

def get_aws_secret(secret_name: str, ):
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name='ap-south-1'
    )

    try:
        get_secret_value_response = client.get_secret_value(SecretId=secret_name)
    except Exception as e:
        raise Exception(f"Error retrieving secret {secret_name}: {e}")

    secret = get_secret_value_response.get('SecretString')
    if secret:
        return json.loads(secret)
    raise Exception("Secret not found")
