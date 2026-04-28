# views.py
from django.shortcuts import get_object_or_404
from django.db import transaction
from rest_framework.response import Response
from rest_framework import status
from memory_map.models import MemoryMap, MemoryMapRecipients
from memory_map.apis.serializers.recipients import RecipientSerializer, RecipientBulkSerializer


from userauth.apis.views.views import SecuredView

class MemoryMapRecipientsAPIView(SecuredView):

    def get(self, request):
        user = self.get_current_user(request)

        memory_map = get_object_or_404(MemoryMap, user=user, is_deleted=False)

        recipients = MemoryMapRecipients.objects.filter(
            memory_map=memory_map, is_deleted=False
        ).order_by("-created_at")

        serializer = RecipientSerializer(recipients, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


#----------------POST(bulk replace)------------------------------------------------
    @transaction.atomic
    def post(self, request):
        user = self.get_current_user(request)

        memory_map = get_object_or_404(MemoryMap, user=user, is_deleted=False)

        serializer = RecipientBulkSerializer(
            data=request.data,
            context={"memory_map": memory_map, "owner": user}
        )
        serializer.is_valid(raise_exception=True)
        recipients = serializer.save()

        return Response(
            {"message": "Recipients updated successfully", 
             "count": len(recipients)
            },
            status=status.HTTP_201_CREATED
        )
    

