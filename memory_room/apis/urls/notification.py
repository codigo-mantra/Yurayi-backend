from django.urls import path
from memory_room.apis.views.notification import (
    NotificationListView,UpdateNotificationView,NotificationMarkAllReadView,NotificationStreamView
)

urlpatterns = [
    path('user/notifications/', NotificationListView.as_view(), name='user_notifications'),
    path('user/notifications/updation/<int:notification_id>/', UpdateNotificationView.as_view(), name='notification_updation'),
    path('user/notifications/marks-as-read/', NotificationMarkAllReadView.as_view(), name='marks_as_read'),
    path('user/notifications/stream/', NotificationStreamView.as_view(), name='notification_stream'),
    
]