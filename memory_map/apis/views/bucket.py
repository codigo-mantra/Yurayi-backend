from rest_framework.response import Response
from rest_framework import status

from memory_map.models import MemoryMap , MemoryMapBucketInfo
from memory_map.apis.serializers.bucket import BucketListCreateSerializer ,BucketListSerializer
from userauth.apis.views.views import SecuredView


class BucketListCreateAPIView(SecuredView):

    def post(self, request):
        user = self.get_current_user(request)

        memory_map, _ = MemoryMap.objects.get_or_create(user=user)

        serializer = BucketListCreateSerializer(
            data=request.data,
            context={"memory_map": memory_map}
        )

         
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        bucket = serializer.save()
        return Response(
            {
                "id": bucket.id,
                "location_name": bucket.location_name,
                "latitude": bucket.latitude,
                "longitude": bucket.longitude,
                "is_visited": bucket.is_visited,
                "tagged_friends": bucket.tagged_friends,
                "message": "Bucket item created successfully"
            },
            status=status.HTTP_201_CREATED
        )




class BucketListAPIView(SecuredView):

    def get(self, request):
        user = self.get_current_user(request)

        memory_map, _ = MemoryMap.objects.get_or_create(user=user)

        bucket_items = MemoryMapBucketInfo.objects.filter(
            memory_map=memory_map,
            is_deleted=False
        )

        search = request.query_params.get("search", "").strip()
        if search:
             bucket_items = bucket_items.filter(location_name__icontains=search)

        is_visited = request.query_params.get("is_visited")
        if is_visited:
            is_visited = is_visited.lower()

            if is_visited not in ["true", "false"]:
                return Response(
                    {"error": "is_visited must be 'true' or 'false'"},
                    status=status.HTTP_400_BAD_REQUEST
                )
            bucket_items = bucket_items.filter(
                is_visited=(is_visited == "true")
            )
            
        serializer = BucketListSerializer(bucket_items, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    


    


            
        













           




