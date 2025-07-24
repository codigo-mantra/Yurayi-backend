from userauth.models import Assets
from memory_room.apis.serializers.memory_room import AssetSerializer
from memory_room.models import TimeCapSoulTemplateDefault,CustomTimeCapSoulTemplate,TimeCapSoul

from rest_framework import serializers

class TimeCapSoulTemplateDefaultReadOnlySerializer(serializers.ModelSerializer):
    cover_image = AssetSerializer()
    class Meta:
        model = TimeCapSoulTemplateDefault
        fields = ('id', 'name', 'summary', 'cover_image')
    
    def get_cover_image_url(self, obj):
        cover_image_url = None

        if obj.cover_image:
            cover_image_url =  obj.cover_image.s3_url
        return cover_image_url


class TimeCapSoulCreationSerializer(serializers.Serializer):
    """
    Serializer to handle creation of Time CapSoul.
    Can be based on a template or from scratch.
    """
    time_capsoul_template_id = serializers.IntegerField(required=False)
    name = serializers.CharField(required=False)
    summary = serializers.CharField(required=False)
    cover_image_id = serializers.IntegerField(required=False)

    def validate(self, data):
        user = self.context['user']
        template_id = data.get('time_capsoul_template_id')

        if template_id:
            data['time_capsoul'] = self._create_from_default_template(template_id, user)
        else:
            missing_fields = [f for f in ['name', 'summary', 'cover_image'] if not data.get(f)]
            if missing_fields:
                raise serializers.ValidationError({field: f'{str(field).capitalize()} field is required.' for field in missing_fields})

            data['time_capsoul'] = self._create_custom_room(data, user)

        return data

    def _create_from_default_template(self, template_id, user):
        """
        Create time-capsoul from a default template.
        """
        default = TimeCapSoulTemplateDefault.objects.filter(id=template_id).first()
        if not default:
            raise serializers.ValidationError({'template_id': 'TimeCapsoul template id is invalid'})

        custom = CustomTimeCapSoulTemplate.objects.create(
            name=default.name, slug=default.slug, summary=default.summary,
            cover_image=default.cover_image, default_template=default
        )
        print(f'\nTime-capsoul Custom Template created: {custom}')
        return TimeCapSoul.objects.create(user=user, capsoul_template=custom)

    def _create_custom_room(self, data, user):
        """
        Create a time-capsoul from scratch using custom inputs.
        """
        try:
            image_asset = Assets.objects.get(id=data['cover_image_id']) 
        except (Assets.DoesNotExist, Assets.MultipleObjectsReturned):
            raise serializers.ValidationError({'cover_image': 'Cover-image id is invalid'})

        custom = CustomTimeCapSoulTemplate.objects.create(
            name=data['name'], summary=data['summary'],
            cover_image=image_asset, default_template=None
        )
        return TimeCapSoul.objects.create(user=user, capsoul_template=custom)

      
class CustomTimeCapSoulTemplateSerializer(serializers.ModelSerializer):
    cover_image = AssetSerializer()
    class Meta:
        model = CustomTimeCapSoulTemplate
        fields = ['id', 'name', 'slug', 'summary', 'cover_image']

class TimeCapSoulSerializer(serializers.ModelSerializer):
    status = serializers.SerializerMethodField()
    capsoul_template = CustomTimeCapSoulTemplateSerializer()


    class Meta:
        model = TimeCapSoul
        fields = ['id', 'status', 'created_at', 'updated_at', 'capsoul_template']
    
    def get_status(self, obj):
        return obj.get_status_display()