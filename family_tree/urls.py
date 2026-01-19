from django.urls import path,include


urlpatterns = [
    
    #  apis endpoints
    path('', include('family_tree.apis.urls.family_tree')), # family-tree apis
]
