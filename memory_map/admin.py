from django.contrib import admin
from .models import (
    MemoryMap,
    MemoryMapPinnedLocationInfo,
    MemoryMapRecipients,
    MemoryMapBucketInfo,
    MemoryMediaDetails
)

admin.site.register(MemoryMap)
admin.site.register(MemoryMapPinnedLocationInfo)
admin.site.register(MemoryMapRecipients)
admin.site.register(MemoryMapBucketInfo)
admin.site.register(MemoryMediaDetails)