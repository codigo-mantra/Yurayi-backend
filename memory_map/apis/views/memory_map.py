from rest_framework.views import APIView 
from rest_framework.response import Response
from rest_framework import status
# from django.db import IntegrityError, transaction

from memory_map.models import MemoryMap, MemoryMapPinnedLocationInfo
from memory_map.apis.serializers.memory_map import MemoryMapSerializer, MemoryMapLocationCreateSerializer,MemoryMapLocationListSerializer 
from userauth.apis.views.views import SecuredView



class MemoryMapAPIView(SecuredView):

    # def get(self, request):
        # user = self.get_current_user(request)

        # try:
        #     memory_map = MemoryMap.objects.get(user=user, is_deleted=False)
        # except MemoryMap.DoesNotExist:
        #     return Response({"detail": "Memory Map not found"},status=status.HTTP_404_NOT_FOUND)

        # serializer = MemoryMapSerializer(memory_map)
        # return Response(serializer.data, status=status.HTTP_200_OK)

    def get(self, request):
        user = self.get_current_user(request)

        memory_map, _ = MemoryMap.objects.get_or_create(
            user=user,
            defaults={
                "title": "My Memory Map",
                "description": ""})

        serializer = MemoryMapSerializer(memory_map)
        return Response(serializer.data, status=status.HTTP_200_OK)
        
    def put(self, request):
        user = self.get_current_user(request)

        try:
            memory_map, _ = MemoryMap.objects.get_or_create(user=user)
        except MemoryMap.DoesNotExist:
            return Response({"detail":"Memory Map not found"},status=status.HTTP_404_NOT_FOUND)
        
        serializer = MemoryMapSerializer(memory_map,data=request.data,partial=True)
        if serializer.is_valid():
            serializer.save()
        else:
            print(serializer.errors) 
            return Response(serializer.data, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class MemoryMapLocationCreateAPIView(SecuredView):

    def post(self, request):
        user = self.get_current_user(request)

        try:
            memory_map, _ = MemoryMap.objects.get_or_create(user=user)
            serializer = MemoryMapLocationCreateSerializer(
                data=request.data,
                context={"memory_map": memory_map}
            )
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_201_CREATED)

            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        except Exception as e:
            return Response({"detail": str(e)}, status=status.HTTP_400_BAD_REQUEST)
        

class MemoryMapLocationListAPIView(SecuredView):

    def get(self, request):
        user = self.get_current_user(request)

        memory_map, _ = MemoryMap.objects.get_or_create(user=user)
        locations = MemoryMapPinnedLocationInfo.objects.filter(
            memory_map=memory_map,
            is_deleted=False
        )

        search = request.query_params.get("search", "").strip()
        if search:
            locations = locations.filter(location_name__icontains=search)

        serializer = MemoryMapLocationListSerializer(locations, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)







    


    
    
    



        



    




            


        





        

        


        


            










