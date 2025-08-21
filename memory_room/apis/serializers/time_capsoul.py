import os
from django.utils import timezone
from userauth.models import Assets
from django.conf import settings
from django.shortcuts import get_object_or_404

from django.core.files.images import ImageFile 
from timecapsoul.utils import MediaThumbnailExtractor
from memory_room.apis.serializers.memory_room import AssetSerializer
from memory_room.models import (
    TimeCapSoulTemplateDefault,CustomTimeCapSoulTemplate,TimeCapSoul,TimeCapSoulRecipient,RecipientsDetail,
    TimeCapSoulMediaFile,TimeCapSoulDetail, TimeCapSoulMediaFileReplica, TimeCapSoulReplica,
    )
from memory_room.crypto_utils import encrypt_and_upload_file, decrypt_and_get_image, generate_signed_path, decrypt_frontend_file
from memory_room.utils import upload_file_to_s3_bucket, get_file_category,get_readable_file_size_from_bytes, S3FileHandler

from rest_framework import serializers
from memory_room.utils import upload_file_to_s3_bucket, get_file_category, generate_unique_slug


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
    cover_image = serializers.IntegerField(required=False)

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
            image_asset = Assets.objects.get(id=data['cover_image']) 
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


class TimeCapSoulReplicaReadOnlySerializer(serializers.ModelSerializer):
    cover_image = AssetSerializer()

    class Meta:
        model = TimeCapSoulReplica
        fields = [
            'id',
            'name',
            'slug',
            'summary',
            'status',
            'cover_image',
            'created_at',
            'updated_at',
        ]
        read_only_fields = fields


class TimeCapSoulSerializer(serializers.ModelSerializer):
    status = serializers.SerializerMethodField()
    name = serializers.SerializerMethodField()
    summary = serializers.SerializerMethodField()
    cover_image = serializers.SerializerMethodField()
    is_default_template = serializers.SerializerMethodField()
    unlocked_data = serializers.SerializerMethodField()
    time_capsoul_replica = serializers.SerializerMethodField()



    class Meta:
        model = TimeCapSoul
        fields = ['id', 'status','is_default_template', 'unlocked_data', 'name', 'summary', 'cover_image','created_at', 'updated_at', 'time_capsoul_replica']
    
    def get_time_capsoul_replica(self, obj):
        try:
            replica = TimeCapSoulReplica.objects.get(parent_time_capsoul = obj)
        except TimeCapSoulReplica.DoesNotExist:
            replica = {}
        else:
            replica = TimeCapSoulReplicaReadOnlySerializer(replica).data
        finally:
            return replica

    
    def get_status(self, obj):
        return obj.get_status_display()
    
    def get_is_default_template(self, obj):
        return True if obj.capsoul_template.default_template else False
    
    def get_unlocked_data(self, obj):
        details = getattr(obj, 'details', None)
        if not details:
            return None
        return {
            "is_locked": details.is_locked,
            "unlock_date": details.unlock_date,
        }
    def get_name(self, obj):
        return obj.capsoul_template.name
    
    def get_summary(self, obj):
        return obj.capsoul_template.summary
    
    def get_cover_image(self, obj):
        cover_image = obj.capsoul_template.cover_image
        return AssetSerializer(cover_image).data


class TimeCapSoulUpdationSerializer(serializers.ModelSerializer):
    """
    Updates a TimeCapSoul's template, or creates a replica if the timecapsoul is locked.
    """
    name = serializers.CharField(required=False)
    summary = serializers.CharField(required=False)
    cover_image = serializers.IntegerField(required=False)

    class Meta:
        model = TimeCapSoul
        fields = ('name', 'summary', 'cover_image')

    def validate_cover_image(self, value):
        try:
            return Assets.objects.get(id=value, asset_types='Time CapSoul Cover')
        except Assets.DoesNotExist:
            raise serializers.ValidationError("Cover image with this ID does not exist.")

    def update(self, instance, validated_data):
        if instance.capsoul_template.default_template is None:
            time_capsoul_detail: TimeCapSoulDetail = self.context['time_capsoul_detial']
            user = instance.user

            name = validated_data.get('name', instance.capsoul_template.name)
            summary = validated_data.get('summary', instance.capsoul_template.summary)
            cover_image = validated_data.get('cover_image')

            if isinstance(cover_image, int):
                cover_image = self.validate_cover_image(cover_image)

            # If locked, create or get replica
            if time_capsoul_detail.is_locked:
                replica_instance, created = TimeCapSoulReplica.objects.get_or_create(
                    parent_time_capsoul=instance,
                    defaults={
                        'name': name,
                        'user': user,
                        'summary': summary,
                        'cover_image': cover_image,
                        'status': instance.status,

                    }
                )
                replica_instance.slug = generate_unique_slug(replica_instance)
                replica_instance.save()
                
                self.context['replica_instance'] = replica_instance
            else:
                # Otherwise, update existing template
                template = instance.capsoul_template
                template.name = name
                template.summary = summary
                if cover_image:
                    template.cover_image = cover_image
                template.save()

        return instance
  


class TimeCapSoulMediaFileSerializer(serializers.ModelSerializer):
    """
    Handles creation of TimeCapSoulMediaFile, including upload to S3.
    """
    iv = serializers.CharField(write_only=True, required=True)


    class Meta:
        model = TimeCapSoulMediaFile
        fields = ('file','iv')


    def create(self, validated_data):
        user = self.context['user']
        file = validated_data.pop('file', None)
        iv = validated_data.pop('iv')
        time_capsoul = self.context['time_capsoul']
        validated_data['user'] = user
        validated_data['time_capsoul'] = time_capsoul
      
        if not file:
            raise serializers.ValidationError({"file": "No file provided."})
        
        try:
            #Decrypt using shared AES key + IV
            decrypted_bytes = decrypt_frontend_file(file, iv)
        except Exception as e:
            raise serializers.ValidationError({'decryption_error': f'File decryption failed: {str(e)}'})
        
        file_type = get_file_category(file.name)
        if file_type == 'invalid':
            raise serializers.ValidationError({'file_type': 'File type is invalid.'})



        if file:
            validated_data['file_size'] = get_readable_file_size_from_bytes(len(decrypted_bytes))
            s3_key = f"{user.s3_storage_id}/time-capsoul-files/{file.name}"
            s3_key = s3_key.replace(" ", "_") # remove white spaces

            try:
                # Upload decrypted file
                upload_media_obj = encrypt_and_upload_file(
                    key=s3_key,
                    plaintext_bytes=decrypted_bytes,
                    content_type=file.content_type,
                    file_category=file_type
                )
            except Exception as e:
                print(f'[Upload Error] {e}')
                raise serializers.ValidationError({'upload_error': "File upload failed. Invalid file."})

            
            validated_data['title'] = file.name
            validated_data['file_type'] = file_type
            validated_data['s3_key'] = s3_key
            validated_data['file'] = file

            # s3_url, file_type,s3_key = upload_file_to_s3_bucket(file, folder='memory_media_files')
            # validated_data['s3_url'] = s3_url
            
            # validated_data['title'] =  validated_data['s3_key'].split('/')[-1]
            



            # Set the file field 
            if file_type == 'audio':
                try:
                    # Extract thumbnail 
                    ext = os.path.splitext(file.name)[1]
                    extractor = MediaThumbnailExtractor(file, ext)
                    thumbnail_data = extractor.extract()

                    if thumbnail_data:
                        from django.core.files.base import ContentFile
                        from userauth.models import Assets 

                        image_file = ContentFile(thumbnail_data, name=f"thumbnail_{file.name}.jpg")
                        asset = Assets.objects.create(image=image_file, asset_types='TimeCapsoul/Thubmnail/Audio')
                        validated_data['thumbnail'] = asset


                        # validated_data['cover_image'] = asset
                        # print(f'S3 url: ',asset.s3_url)
                        # validated_data['thumbnail_url'] = asset.s3_url
                        # print(f'thubmnail: {validated_data['thumbnail_url']}')
                        # validated_data['thumbnail_key'] = asset.s3_key
                except Exception as e:
                    print(f'\n Exception while extracting thumbnail: \n{e}')
            
                
        return super().create(validated_data)


class TimeCapSoulMediaFileReplicaSerializer(serializers.ModelSerializer):
    thumbnail = AssetSerializer()
    class Meta:
        model = TimeCapSoulMediaFileReplica
        fields = ('id', 'file_type', 's3_url', 'title', 'description', 'thumbnail', 'file_size')



class TimeCapSoulMediaFileReadOnlySerializer(serializers.ModelSerializer):
    thumbnail = AssetSerializer()
    replica_media = serializers.SerializerMethodField()
    s3_url = serializers.SerializerMethodField()
    class Meta:
        model = TimeCapSoulMediaFile
        fields = ('id', 'file_type', 's3_url', 'title', 'description', 'thumbnail', 'file_size', 'replica_media')

    def get_s3_url(self, obj):
        import time, base64, hmac, hashlib

        exp = int(time.time()) + 60*5  # 5 minutes expiry
        raw = f"{obj.s3_key}:{exp}"
        sig = base64.urlsafe_b64encode(
            hmac.new(settings.SECRET_KEY.encode(), raw.encode(), hashlib.sha256).digest()
        ).decode().rstrip("=")
        return f"/api/v0/time-capsoul/api/media/serve/{obj.s3_key[37:]}?exp={exp}&sig={sig}"

    def get_replica_media(self, obj):
        try:
            replica_media_file = TimeCapSoulMediaFileReplica.objects.get(parent_media_file = obj)
        except TimeCapSoulMediaFileReplica.DoesNotExist:
            response = {}
        else:
            response = TimeCapSoulMediaFileReplicaSerializer(replica_media_file).data
        finally:
            return response



class TimeCapSoulMediaFilesReadOnlySerailizer(serializers.ModelSerializer):
    time_capsoul = TimeCapSoulSerializer()
    media_files = TimeCapSoulMediaFileReadOnlySerializer(many=True)

    class Meta:
        model = TimeCapSoulDetail
        fields = ('time_capsoul', 'media_files')


class TimeCapsoulMediaFileUpdationSerializer(serializers.ModelSerializer):
    cover_type = serializers.CharField(required = False)

    class Meta:
        model = TimeCapSoulMediaFile
        fields = ('description',  'cover_type')

    def update(self, instance, validated_data):
        time_capsoul_detail = self.context['time_capsoul_detial']
        cover_type  = validated_data.get('cover_type', None)
        validated_data.pop('cover_type', None)
        description = validated_data.get('description', instance.description)

        if time_capsoul_detail.is_locked:
            # Create or retrieve replica
            replica, created = TimeCapSoulMediaFileReplica.objects.get_or_create(
                parent_media_file=instance,
                defaults={
                    'user': instance.user,
                    'time_capsoul': instance.time_capsoul,
                    'file': instance.file,
                    'file_type': instance.file_type,
                    'title': instance.title,
                    'description': validated_data.get('description'),
                    'thumbnail': instance.thumbnail,
                    'file_size': instance.file_size,
                    's3_url': instance.s3_url,
                    's3_key': instance.s3_key,
                    'is_cover_image': instance.is_cover_image
                }
            )
            self.context['replica_media_file'] = replica
        else:
            # Update instance normally
            instance.description = description
            time_capsoul_template = time_capsoul_detail.time_capsoul.capsoul_template

            if cover_type == 'audio':
                if instance.thumbnail is not None:
                    time_capsoul_template.cover_image = instance.thumbnail
                    instance.is_cover_image = True
            elif instance.file_type == 'image' and not instance.is_cover_image:
                asset = Assets.objects.create(title=instance.title, image=instance.file)
                time_capsoul_template.cover_image = asset
                instance.thumbnail = asset

            time_capsoul_template.save()

        instance.save()
        return instance



class TimeCapsoulUnlockSerializer(serializers.ModelSerializer):
    unlock_date = serializers.DateTimeField(required=True)

    class Meta:
        model = TimeCapSoulDetail
        fields = ('unlock_date',)

    def validate(self, attrs):
        unlock_date = attrs.get('unlock_date')
        instance = self.instance  # This is the current TimeCapSoulDetail object

        if unlock_date is None:
            raise serializers.ValidationError({
                "unlock_date": "Unlock date is required."
            })


        # Enforce future date
        if unlock_date <= timezone.now():
            raise serializers.ValidationError({
                "unlock_date": "Unlock date must be a future date and time."
            })

        # Prevent relocking if already locked
        if instance and instance.is_locked:
            raise serializers.ValidationError("This TimeCapsoul is already locked and cannot be locked again.")

        return attrs

    def update(self, instance, validated_data):
        # Locking the TimeCapsoul for the first and only time
        instance.unlock_date = validated_data['unlock_date']
        instance.is_locked = True
        time_capsoul = instance.time_capsoul
        time_capsoul.status = 'sealed'
        time_capsoul.save()
        instance.save()
        return instance


class TimeCapSoulRecipientSerializer(serializers.ModelSerializer):
    class Meta:
        model = TimeCapSoulRecipient
        fields = ['id', 'name', 'email']


class RecipientsDetailSerializer(serializers.ModelSerializer):
    recipients = TimeCapSoulRecipientSerializer(many=True)

    class Meta:
        model = RecipientsDetail
        fields = ['id', 'recipients']  

    def create(self, validated_data):
        time_capsoul = self.context.get('time_capsoul')
        if not time_capsoul:
            raise serializers.ValidationError("TimeCapsoul context is required.")

        # ✅ Get existing RecipientsDetail created via signal
        recipients_detail = get_object_or_404(RecipientsDetail, time_capsoul=time_capsoul)

        recipients_data = validated_data.pop('recipients', [])

        for recipient_data in recipients_data:
            recipient, _ = TimeCapSoulRecipient.objects.get_or_create(**recipient_data)
            recipients_detail.recipients.add(recipient)

        return recipients_detail


    def update(self, instance, validated_data):
        recipients_data = validated_data.pop('recipients', None)

        if recipients_data is not None:
            instance.recipients.clear()
            for recipient_data in recipients_data:
                recipient, _ = TimeCapSoulRecipient.objects.get_or_create(**recipient_data)
                instance.recipients.add(recipient)

        return instance
