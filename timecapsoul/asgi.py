"""
ASGI config for timecapsoul project.

It exposes the ASGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/5.2/howto/deployment/asgi/
"""

import os


from django.core.asgi import get_asgi_application
from channels.auth import AuthMiddlewareStack
from channels.routing import ProtocolTypeRouter, URLRouter
import memory_room.routing  

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'timecapsoul.settings')


application = get_asgi_application()

application = ProtocolTypeRouter({
    "http": get_asgi_application(), # normal https requests
    "websocket": AuthMiddlewareStack( # web-socket 
        URLRouter(
           memory_room.routing.websocket_urlpatterns 
        )
    ),
})