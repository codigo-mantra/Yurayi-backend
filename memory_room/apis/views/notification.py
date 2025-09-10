import time, json
from rest_framework import generics, permissions
from rest_framework.response import Response
from django.utils.timezone import now
from django.shortcuts import get_object_or_404
from django.http import StreamingHttpResponse
from django.utils.timezone import now
from rest_framework import status
from rest_framework import serializers
from django.http import StreamingHttpResponse
from django.utils.timezone import now
import json, time

from memory_room.models import Notification
from userauth.apis.views.views import SecuredView
from memory_room.apis.serializers.notification import NotificationSerializer, NotificationUpdateSerializer

# user-notification-list
class NotificationListView(SecuredView):
    def get(self, request):
        user  = self.get_current_user(request)
        notications = Notification.objects.filter(user=user, is_deleted = False).order_by("-created_at")
        data  = NotificationSerializer(notications, many=True).data
        return Response(data)
        

# update-notification
class UpdateNotificationView(SecuredView):
    
    def post(self, request, notification_id):
        user  = self.get_current_user(request)
        notication = get_object_or_404(Notification, id=notification_id, user = user, is_deleted=False)
        serializer = NotificationUpdateSerializer(instance = notication, data = request.data)
        serializer.is_valid(raise_exception= True)
        serializer.save()
        return Response(serializer.data,  status=status.HTTP_200_OK)
    

#  Mark all as read or clear
class NotificationMarkAllReadView(SecuredView):
    def post(self, request):
        user  = self.get_current_user(request)
        updation_type = request.data.get('updation_type', None)
        if not updation_type:
            raise serializers.ValidationError({'updation_type': "Updation type is required"})
        
        if updation_type == 'marks_as_all_read':
            Notification.objects.filter(user=user, is_read=False, is_deleted = False).update(is_read=True)
            message = {"detail": "All notifications marked as read."}
        elif updation_type == 'clear_all':
            Notification.objects.filter(user=user, is_deleted = False).update(is_deleted=True)
            message = {"detail": "All notifications cleared."}
        else:
            raise serializers.ValidationError({'updation_type': "Invalid value for updation it can marks_as_all_read or clear_all"})
            
        return Response(message)


# notification-stream
class NotificationStreamView(SecuredView):

    def get(self, request, *args, **kwargs):
        user = self.get_current_user(request)
        last_event_id = request.headers.get("Last-Event-ID")

        def event_stream():
            last_check = now()

            # Resume if client sent Last-Event-ID
            if last_event_id:
                try:
                    last_id = int(last_event_id)
                    queryset = Notification.objects.filter(
                        user=user, id__gt=last_id, is_deleted=False
                    ).order_by("created_at")
                    for notif in queryset:
                        yield f"id: {notif.id}\ndata: {json.dumps(NotificationSerializer(notif).data)}\n\n"
                except ValueError:
                    pass
            else:
                # On first connect → send latest 10 notifications
                recent = Notification.objects.filter(user=user, is_deleted=False).order_by("-created_at")[:10]
                for notif in reversed(recent):  # send oldest first
                    yield f"id: {notif.id}\ndata: {json.dumps(NotificationSerializer(notif).data)}\n\n"

            # Continuous stream (polling)
            while True:
                new_notifications = Notification.objects.filter(
                    user=user, created_at__gt=last_check, is_deleted=False
                ).order_by("created_at")

                if new_notifications.exists():
                    for notif in new_notifications:
                        yield f"id: {notif.id}\ndata: {json.dumps(NotificationSerializer(notif).data)}\n\n"
                    last_check = now()
                else:
                    # heartbeat to keep connection alive
                    yield ": keep-alive\n\n"

                time.sleep(10)  # polling interval

        response = StreamingHttpResponse(event_stream(), content_type="text/event-stream")
        response["Cache-Control"] = "no-cache"
        return response
