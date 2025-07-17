import io
import boto3
import mimetypes
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

def get_file_category(file_name):
    import mimetypes

    content_type = mimetypes.guess_type(file_name)[0] or ''
    if content_type.startswith('image/'):
        return 'image'
    elif content_type.startswith('video/'):
        return 'video'
    elif content_type.startswith('audio/'):
        return 'audio'
    elif content_type in ['application/pdf', 'application/msword',
                          'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
                          'application/vnd.ms-excel']:
        return 'document'
    else:
        return 'other'
    
def upload_file_to_s3_bucket(file, folder=None):
    import io
    import boto3
    import mimetypes
    from django.conf import settings

    # Step 1: Setup file name and content type
    original_file_name = file.name
    if folder:
        file_name = f"{folder}/{original_file_name}"
    else:
        file_name = original_file_name

    file_category = get_file_category(original_file_name)
    s3_key = f"{file_category}/{file_name}"
    content_type = mimetypes.guess_type(original_file_name)[0] or 'application/octet-stream'

    # Step 2: Prepare file buffer
    file.seek(0)
    buffer = io.BytesIO(file.read())

    # Step 3: Upload to S3
    s3 = boto3.client(
        's3',
        aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
        aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
        region_name=settings.AWS_S3_REGION_NAME
    )

    try:
        s3.upload_fileobj(
            buffer,
            settings.AWS_STORAGE_BUCKET_NAME,
            s3_key,
            ExtraArgs={
                'ContentType': content_type,
                'ACL': 'public-read'  # Change to 'private' if needed
            }
        )
    except Exception as e:
        raise Exception(f"S3 upload failed: {str(e)}")

    # Step 4: Build full S3 URL
    s3_url = f"https://{settings.AWS_STORAGE_BUCKET_NAME}.s3.{settings.AWS_S3_REGION_NAME}.amazonaws.com/{s3_key}"

    return (s3_url, file_category, s3_key)

def determine_download_chunk_size(file_size):
    """
    Dynamically determine chunk size based on file size (in bytes).
    """
    if file_size <= 10 * 1024 * 1024:      # <= 10 MB
        return 512 * 1024                 # 512 KB
    elif file_size <= 100 * 1024 * 1024:   # <= 100 MB
        return 1 * 1024 * 1024            # 1 MB
    elif file_size <= 500 * 1024 * 1024:   # <= 500 MB
        return 2 * 1024 * 1024            # 2 MB
    else:
        return 5 * 1024 * 1024            # 5 MB for large files
