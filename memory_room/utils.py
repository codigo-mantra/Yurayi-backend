import string, random
from django.conf import settings
from django.utils.text import slugify

def generate_unique_slug(instance, queryset=None):
    """
    Generate a unique slug for a model instance.
    """
    slug_base = slug = slugify(instance.name)

    slug = slug_base
    model_class = instance.__class__
    
    if queryset is None:
        queryset = model_class.objects.all()

    str_letters = string.ascii_lowercase
    while queryset.filter(slug = slug).exclude(pk=instance.pk).exists():
        slug = slugify(slug + random.choice(str_letters) + str(random.randint(1,9)))
    
    return slug
# utils/s3_upload.py

import io
import boto3
import mimetypes
from django.conf import settings

def upload_file_to_s3_bucket(file, folder="media"):
    """Upload file to S3 and return the S3 URL."""
    file_content = file.read()
    buffer = io.BytesIO(file_content)

    file_name = f"{folder}/{file.name}"
    content_type = mimetypes.guess_type(file.name)[0] or 'application/octet-stream'

    s3 = boto3.client(
        's3',
        aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
        aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
        region_name=settings.AWS_S3_REGION_NAME,
    )

    try:
        s3.upload_fileobj(
            buffer,
            settings.AWS_STORAGE_BUCKET_NAME,
            file_name,
            ExtraArgs={'ContentType': content_type, 'ACL': 'public-read'}
        )
    except Exception as e:
        print(f'Exception while uploading file to S3: {e}')
        return None
    else:
        s3_file_url = f"https://{settings.AWS_STORAGE_BUCKET_NAME}.s3.{settings.AWS_S3_REGION_NAME}.amazonaws.com/{file_name}"

    return s3_file_url
