import os
import mimetypes
import logging
from email.mime.image import MIMEImage
from celery import shared_task

from django.conf import settings
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string


# logger = logging.getLogger(__name__)

@shared_task(bind=True, max_retries=3)
def send_html_email_task(self, subject,  template_name, to_email=None, context=None, inline_images=None, email_list=None):
    """
    Celery task to send an HTML email using a template and context.

    :param subject: Subject of the email
    :param to_email: Recipient's email address (string or list)
    :param template_name: Path to HTML template (e.g. 'emails/welcome_email.html')
    :param context: Context dictionary for the template
    :param inline_images: Optional dict for CID images: {'cid_name': '/absolute/path/to/image.png'}
    """
    try:
        from_email = settings.DEFAULT_FROM_EMAIL

        # Handle recipient list
        if email_list is None:
            if isinstance(to_email, str):
                to_email = [to_email]
        else:
            to_email = email_list

        if context is None:
            context = {}

        # Render HTML content
        html_content = render_to_string(template_name, context)

        # Create email object
        email = EmailMultiAlternatives(subject, "", from_email, to_email)
        email.attach_alternative(html_content, "text/html")

        # Attach inline CID images if provided
        if inline_images:
            for cid, image_path in inline_images.items():
                if os.path.exists(image_path):
                    with open(image_path, "rb") as img:
                        img_data = img.read()
                        content_type, encoding = mimetypes.guess_type(image_path)
                        maintype, subtype = content_type.split("/") if content_type else ("image", "png")
                        mime_image = MIMEImage(img_data, _subtype=subtype)
                        mime_image.add_header("Content-ID", f"<{cid}>")
                        mime_image.add_header("Content-Disposition", "inline", filename=os.path.basename(image_path))
                        email.attach(mime_image)

        email.send()
        return True

    except Exception as e:
        # logger.exception(f"Error sending email: {e}")
        # Retry if email sending fails (optional)
        raise self.retry(exc=e, countdown=60)
