# consumers.py
from channels.generic.websocket import AsyncWebsocketConsumer
import json

class DownloadProgressConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.file_id = self.scope['url_route']['kwargs']['file_id']
        self.room_group_name = f"progress_{self.file_id}"

        await self.channel_layer.group_add(
            self.room_group_name,
            self.channel_name
        )
        await self.accept()

    async def disconnect(self, close_code):
        await self.channel_layer.group_discard(
            self.room_group_name,
            self.channel_name
        )

    async def send_progress(self, event):
        await self.send(text_data=json.dumps(event['content']))
