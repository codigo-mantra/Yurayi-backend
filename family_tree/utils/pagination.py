from rest_framework.pagination import PageNumberPagination


class FamilyTreeDiaryPagination(PageNumberPagination):
    page_size = 8              
    page_size_query_param = "page_size"
    max_page_size = 50                
    page_query_param = "page"


class GalleryPagination(PageNumberPagination):
    page_size = 8
    page_size_query_param = "page_size"
    max_page_size = 50

class FamilyTreeGalleryPagination(PageNumberPagination):
    page_size = 8
    page_size_query_param = "page_size"
    max_page_size = 100