from django.apps import AppConfig


class UserauthConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'userauth'

    def ready(self):
        import userauth.signals
        import pillow_heif
        pillow_heif.register_heif_opener()
