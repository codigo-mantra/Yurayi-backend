import logging
from django.db import DatabaseError
from django.core.exceptions import ValidationError
from memory_room.models import Notification
from django.core.cache import cache
from memory_room.notification_message import NOTIFICATIONS


logger = logging.getLogger(__name__)

class NotificationService:
    @staticmethod
    def create_notification(user, category, category_type, title, message, memory_room=None, time_capsoul=None):
        """
        Safely create a system-generated notification.
        Returns:
            Notification instance if created,
            None if failed.
        """
        try:
            if not user:
                raise ValueError("User is required to create a notification")

            if not category or not category_type:
                raise ValueError("Both category and category_type are required")

            notification = Notification.objects.create(
                user=user,
                category=category,
                category_type=category_type,
                title=title,
                message=message,
                memory_room=memory_room,
                time_capsoul=time_capsoul,
            )
            cache_key = f'{notification.user.email}__notifications'
            cache.delete(cache_key)
            return notification

        except (ValidationError, DatabaseError, ValueError) as e:
            logger.error(
                "Failed to create notification",
                extra={
                    "user_id": getattr(user, "id", None),
                    "category": category,
                    "category_type": category_type,
                    "error": str(e),
                },
                exc_info=True,
            )
            return None
   
    @staticmethod
    def create_notification_with_key(notification_key, user, memory_room=None, time_capsoul=None, custom_message=None, allow_multiple=None):
        """
        Safely create a system-generated notification.
        Returns:
            Notification instance if created,
            None if failed.
        """
        try:
            notification_data = NOTIFICATIONS[f'{notification_key}']
            if not user:
                raise ValueError("User is required to create a notification")
          
            category = notification_data['category']
            category_type = notification_data['type']
            title = notification_data['title']
            if custom_message is None:
                message = notification_data['message']
            else:
                message = custom_message
            
            if allow_multiple:
                notification = Notification.objects.create(
                user=user,
                category=category,
                category_type=category_type,
                title=title,
                message=message,
                memory_room=memory_room,
                time_capsoul=time_capsoul,
            )
            else:
                notification, created = Notification.objects.get_or_create(
                    user=user,
                    category=category,
                    category_type=category_type,
                    title=title,
                    message=message,
                    memory_room=memory_room,
                    time_capsoul=time_capsoul,
                )
            
            cache_key = f'{notification.user.email}__notifications'
            cache.delete(cache_key)
            return notification

        except (ValidationError, DatabaseError, ValueError) as e:
            logger.error(
                "Failed to create notification with key",
                extra={
                    "user_id": getattr(user, "id", None),
                    "notification_key": notification_key,
                    "error": str(e),
                },
                exc_info=True,
            )
            return None
