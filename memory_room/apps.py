from django.apps import AppConfig


class MemoryRoomConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'memory_room'

    def ready(self):
        import memory_room.signals 
