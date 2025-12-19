from django.apps import AppConfig
from django.core.cache import cache
from django.conf import settings

class MemoryRoomConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'memory_room'

    def ready(self):
        cache.clear()
        print(f'\n ------- Cache Cleared -----')
        # clear_all_cache.apply_async()
        if not settings.DEBUG:
            # cache.clear()
            # print('\n---cache cleared----')
            pass
        import memory_room.signals 
