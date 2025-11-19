import os
import time

from django.utils import timezone
from userauth.models import Assets
from django.conf import settings
import base64, hmac, hashlib
from datetime import datetime, timedelta
from django.shortcuts import get_object_or_404
from userauth.models import User
from django.core.cache import cache
from memory_room.helpers import (
    upload_file_to_s3_kms,create_parent_media_files_replica_upload_to_s3_bucket,upload_file_to_s3_kms_chunked,create_time_capsoul,create_time_capsoul_media_file, generate_unique_capsoul_name,user_capsoul_name_list, generate_unique_file_name, get_recipient_capsoul_ids
)

from memory_room.signals import update_user_storage
from memory_room.tasks import capsoul_almost_unlock,capsoul_unlocked,update_parent_media_refrences_task

from memory_room.media_helper import decrypt_upload_and_extract_audio_thumbnail_chunked
from memory_room.upload_helper import decrypt_upload_and_extract_audio_thumbnail_chunked as media_uploader

from django.core.files.images import ImageFile 
from timecapsoul.utils import MediaThumbnailExtractor
from memory_room.apis.serializers.memory_room import AssetSerializer
from memory_room.models import (
    TimeCapSoulTemplateDefault,CustomTimeCapSoulTemplate,TimeCapSoul,TimeCapSoulRecipient,RecipientsDetail,
    TimeCapSoulMediaFile,TimeCapSoulDetail, TimeCapSoulMediaFileReplica, TimeCapSoulReplica,
    )
from timecapsoul.utils import send_html_email
from memory_room.crypto_utils import encrypt_and_upload_file, decrypt_and_get_image, generate_signed_path, decrypt_frontend_file,save_and_upload_decrypted_file, encrypt_and_upload_file_no_iv, encrypt_and_upload_file_chunked,upload_encrypted_file_chunked,get_media_file_bytes_with_content_type,generate_signature,generate_capsoul_media_s3_key,clean_filename
from memory_room.utils import upload_file_to_s3_bucket, get_file_category,get_readable_file_size_from_bytes, S3FileHandler

from userauth.tasks import send_html_email_task
from rest_framework import serializers
from memory_room.tasks import capsoul_notification_handler
from memory_room.notification_service import NotificationService
from memory_room.utils import upload_file_to_s3_bucket, get_file_category, generate_unique_slug

import logging
logger = logging.getLogger(__name__)



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
        
        # Check if user already has time-capsoul with same template name
        existing_rooms = TimeCapSoul.objects.filter(
            user=user,
            is_deleted = False,
            capsoul_template__default_template=default,
        )

        if existing_rooms.exists():
            capsoul_name = generate_unique_capsoul_name(user, default.name)
        else:
            capsoul_name = default.name

        custom = CustomTimeCapSoulTemplate.objects.create(
            name=capsoul_name, slug=default.slug, summary=default.summary,
            cover_image=default.cover_image, default_template=default
        )
        logger.info('Time-capsoul Custom Template created')
        return TimeCapSoul.objects.create(user=user, capsoul_template=custom)

    def _create_custom_room(self, data, user):
        """
        Create a time-capsoul from scratch using custom inputs.
        """
        try:
            image_asset = Assets.objects.get(id=data['cover_image']) 
        except (Assets.DoesNotExist, Assets.MultipleObjectsReturned):
            raise serializers.ValidationError({'cover_image': 'Cover-image id is invalid'})
        base_name = data.get('name')
        
        
        # Check if user already has time-capsoul with same template name
        new_capsoul_name = base_name
        if len(base_name) > 255:
            raise serializers.ValidationError({'name': "Time-capsoul name is too long. It can be of 255 words only"})
        
        capsoul = TimeCapSoul.objects.filter(
            user = user,
            is_deleted = False
        )
        
        if new_capsoul_name:
            room_exists = TimeCapSoul.objects.filter(
                user=user,
                is_deleted=False,
                capsoul_template__name__iexact=new_capsoul_name
            ).first()

            if room_exists :
                raise serializers.ValidationError({'name': 'You already have a time-capsoul with this name. Please choose a different name.'})
        
        
        

        custom = CustomTimeCapSoulTemplate.objects.create(
            name=base_name, summary=data['summary'],
            cover_image=image_asset, default_template=None
        )
        return TimeCapSoul.objects.create(user=user, capsoul_template=custom)

      
class CustomTimeCapSoulTemplateSerializer(serializers.ModelSerializer):
    cover_image = AssetSerializer()
    class Meta:
        model = CustomTimeCapSoulTemplate
        fields = ['id', 'name', 'slug', 'summary', 'cover_image']



# class TimeCapSoulSerializer(serializers.ModelSerializer):
#     status = serializers.SerializerMethodField()
#     name = serializers.SerializerMethodField()
#     summary = serializers.SerializerMethodField()
#     cover_image = serializers.SerializerMethodField()
#     is_default_template = serializers.SerializerMethodField()
#     unlocked_data = serializers.SerializerMethodField()
#     time_capsoul_replica = serializers.SerializerMethodField()
#     total_files = serializers.SerializerMethodField()
#     is_owner = serializers.SerializerMethodField()
#     tagged_members = serializers.SerializerMethodField()


#     class Meta:
#         model = TimeCapSoul
#         fields = ['id', 'status','total_files','is_owner', 'is_default_template', 'unlocked_data', 'name', 'summary', 'cover_image','created_at', 'updated_at', 'time_capsoul_replica', 'tagged_members']
    
#     def get_tagged_members(self, obj):
#         time_capsoul_recipients = RecipientsDetail.objects.filter(time_capsoul = obj)
#         serializer = RecipientsDetailSerializer(time_capsoul_recipients, many=True)
#         return serializer.data
    
#     def get_is_owner(self, obj):
#         is_owner = False
#         user = self.context('user', None)
#         if user:
#             if user == user:
#                 is_owner = True
#         return is_owner
    
#     def get_total_files(self, obj):
#         # Access related MemoryRoomDetail
#         try:
#             detail = obj.details  
#             return detail.media_files.count()
#         except TimeCapSoulDetail.DoesNotExist:
#             return 0
    
#     def get_time_capsoul_replica(self, obj):
#         try:
#             replica = TimeCapSoulReplica.objects.get(parent_time_capsoul = obj)
#         except TimeCapSoulReplica.DoesNotExist:
#             replica = {}
#         else:
#             replica = TimeCapSoulReplicaReadOnlySerializer(replica).data
#         finally:
#             return replica

    
#     def get_status(self, obj):
#         return obj.get_status_display()
    
#     def get_is_default_template(self, obj):
#         return True if obj.capsoul_template.default_template else False
    
#     def get_unlocked_data(self, obj):
#         details = getattr(obj, 'details', None)
#         if not details:
#             return None
#         return {
#             "is_locked": details.is_locked,
#             "unlock_date": details.unlock_date,
#         }
#     def get_name(self, obj):
#         return obj.capsoul_template.name
    
#     def get_summary(self, obj):
#         return obj.capsoul_template.summary
    
#     def get_cover_image(self, obj):
#         cover_image = obj.capsoul_template.cover_image
#         return AssetSerializer(cover_image).data

class TimeCapSoulSerializer(serializers.ModelSerializer):
    status = serializers.SerializerMethodField()
    name = serializers.SerializerMethodField()
    summary = serializers.SerializerMethodField()
    cover_image = serializers.SerializerMethodField()
    is_default_template = serializers.SerializerMethodField()
    unlocked_data = serializers.SerializerMethodField()
    # time_capsoul_replica = serializers.SerializerMethodField()
    total_files = serializers.SerializerMethodField()
    is_owner = serializers.SerializerMethodField()
    tagged_members = serializers.SerializerMethodField()

    class Meta:
        model = TimeCapSoul
        fields = [
            'id', 'status', 'total_files', 'is_owner',
            'is_default_template', 'unlocked_data',
            'name', 'summary', 'cover_image',
            'created_at', 'updated_at', 'tagged_members'
        ]

    def get_tagged_members(self, obj):
        user = self.context.get('user', None) 
        if obj.user == user:
            capsoul_recipients = TimeCapSoulRecipient.objects.filter(time_capsoul = obj)
        else:
            capsoul_recipients = TimeCapSoulRecipient.objects.filter(time_capsoul = obj, email = user.email)
            
        serializer = TimeCapSoulRecipientSerializer(capsoul_recipients, many=True)
        return serializer.data

    def get_is_owner(self, obj):
        user = self.context.get('user', None)  
        if user:
            if obj.user == user:
                return True
        return False

    def get_total_files(self, obj):
        count = 0
        user = self.context.get('user', None)  
        if obj.user != user:
            recipient = TimeCapSoulRecipient.objects.filter(time_capsoul = obj, email = user.email).first()
            parent_files_id = get_recipient_capsoul_ids(recipient)
            count = len(parent_files_id)

        else:
            try:
                count =  obj.timecapsoul_media_files.filter(is_deleted=False).count()
            except Exception as e:
                pass
        return count
        

    def get_status(self, obj):
        current_user = self.context.get('user')
        if obj.status == 'sealed':
            unlock_date = obj.unlock_date
            current_datetime = timezone.now()  
            
            if unlock_date and current_datetime > unlock_date:
                obj.status = 'unlocked'
                obj.save()
                # recipients = TimeCapSoulRecipient.objects.filter(time_capsoul = obj, is_deleted = False)
                # media_ids = list(obj.timecapsoul_media_files.filter(is_deleted=False).values_list('id', flat=True))
                # print(f'\n media_ids to be updated in recipients: {media_ids}')
                # recipients.update(parent_media_refrences = media_ids)

            
        if current_user == obj.user:
            
            if obj.status == 'unlocked':
                recipients = TimeCapSoulRecipient.objects.filter(time_capsoul = obj, is_deleted = False)
                if recipients.count() > 0:
                    all_is_opend = recipients.values_list('is_opened', flat=True)
                    if False in all_is_opend:
                        return 'Sealed With Love'
            return obj.get_status_display()
        else:
            recipients = TimeCapSoulRecipient.objects.filter(time_capsoul = obj, email= current_user.email).first()
            if  recipients:
                if recipients.is_opened == False:
                    return 'Sealed With Love'
                else:
                    return 'Unlocked'
           
    def get_is_default_template(self, obj):
        return bool(getattr(obj.capsoul_template, "default_template", False))

    def get_unlocked_data(self, obj):
        return {
            "is_locked": obj.is_locked,
            "unlock_date": obj.unlock_date,
        }

    def get_name(self, obj):
        return getattr(obj.capsoul_template, "name", None)

    def get_summary(self, obj):
        return getattr(obj.capsoul_template, "summary", None)

    def get_cover_image(self, obj):
        cover_image = obj.capsoul_template.cover_image
        if cover_image:
            return AssetSerializer(cover_image).data
        return None


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
            raise serializers.ValidationError("Cover image  id is invalid.")

    def update(self, instance, validated_data):
        current_user = self.context.get('current_user')
        user = instance.user
        time_capsoul = instance
        name = validated_data.get('name', instance.capsoul_template.name)
        summary = validated_data.get('summary', instance.capsoul_template.summary)
        cover_image = validated_data.get('cover_image')

        if isinstance(cover_image, int):
            cover_image = self.validate_cover_image(cover_image)
                
        if cover_image is None:
            cover_image = instance.capsoul_template.cover_image


        # If status == unlocked create replica
        if instance.status == 'unlocked':
            
            # create custom template for replica
            new_capsoul_name = validated_data.get('name')
            existing_capsouls = TimeCapSoul.objects.filter(
                user=current_user,
                is_deleted=False,
            ).exclude(id = time_capsoul.id).values_list("capsoul_template__name", flat=True)
            
            recipient_capsouls = TimeCapSoulRecipient.objects.filter(
                email=current_user.email,
            ).exclude(id = time_capsoul.id).values_list("time_capsoul__capsoul_template__name", flat=True)
            
            # existing_names = set(name.lower() for name in list(existing_capsouls) + list(recipient_capsouls))
            existing_names = set(
                (name.lower() for name in list(existing_capsouls) + list(recipient_capsouls) if name)
            )

            if new_capsoul_name in  existing_names:
                raise serializers.ValidationError({'name': 'You already have a time-capsoul with this name. Please choose a different name.'})
            
            replica_instance = create_time_capsoul(
                old_time_capsoul = time_capsoul, # create time-capsoul replica
                current_user = current_user,
                option_type = 'replica_creation',
                capsoul_name = new_capsoul_name,
                capsoul_summary = summary,
                cover_image = cover_image,
            )
            if current_user == time_capsoul.user: # if user is owner of the capsoul
                parent_media_files = TimeCapSoulMediaFile.objects.filter(time_capsoul = time_capsoul, is_deleted = False)
            else:
                recipient = TimeCapSoulRecipient.objects.filter(time_capsoul = time_capsoul, email = current_user.email).first()
                if not recipient:
                    logger.info(f"Recipient not found for tagged capsoul for {time_capsoul.id} and user {current_user.email}")
                    raise serializers.ValidationError({'detail': 'You do not have access to this time-capsoul.'})
                else:
                    # parent_files_id = (
                    #     [int(i.strip()) for i in recipient.parent_media_refrences.split(',') if i.strip().isdigit()]
                    #     if recipient.parent_media_refrences else []
                    # )
                    parent_files_id = get_recipient_capsoul_ids(recipient)
                    parent_media_files = TimeCapSoulMediaFile.objects.filter(
                        time_capsoul=time_capsoul,
                        id__in = parent_files_id,
                    )
            new_media_count = 0
            old_media_count = parent_media_files.count()   
            for parent_file in parent_media_files:
                try:
                    is_media_created = create_time_capsoul_media_file(
                        old_media=parent_file,
                        new_capsoul=replica_instance,
                        current_user = current_user,
                        option_type = 'replica_creation',
                    )
                except Exception as e:
                    logger.exception(F'Exception while creating time-capsoul media-file replica for media-file id {parent_file.id} and user {user.email}')
                    pass
                else:
                    if is_media_created:
                        new_media_count += 1
            print(f"Old media count: {old_media_count}, New media count: {new_media_count}")
        else:
            if current_user == time_capsoul.user:
                if instance.capsoul_template.default_template is None: # create from scratch
                    template = instance.capsoul_template
                    new_capsoul_name = validated_data.get('name')
                   
                    existing_capsouls = TimeCapSoul.objects.filter(
                        user=current_user,
                        is_deleted=False,
                    ).exclude(id = time_capsoul.id).values_list("capsoul_template__name", flat=True)
            
                    recipient_capsouls = TimeCapSoulRecipient.objects.filter(
                        email=current_user.email,
                        is_capsoul_deleted = False,
                    ).exclude(id = time_capsoul.id).values_list("time_capsoul__capsoul_template__name", flat=True)
                    
                    existing_names = set(
                        (name.lower() for name in list(existing_capsouls) + list(recipient_capsouls) if name)
                    )

                    if new_capsoul_name in  existing_names:
                        raise serializers.ValidationError({'name': 'You already have a time-capsoul with this name. Please choose a different name.'})
                            
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
    
    @staticmethod
    def truncate_filename(filename, max_length=100):
        """Truncate filename while preserving extension."""
        name, ext = os.path.splitext(filename)
        if len(filename) > max_length:
            max_name_length = max_length - len(ext)
            name = name[:max_name_length]
        return f"{name}{ext}"
    
    def to_internal_value(self, data):
        file = data.get('file')
        if file:
            file.name = clean_filename(self.truncate_filename(file.name))
        return super().to_internal_value(data)
    
    def validate(self, attrs):
        """Perform validation for file, IV, and type."""
        time_capsoul = self.context.get('time_capsoul')
        file = attrs.get('file')
        iv = attrs.get('iv')

        if not file:
            raise serializers.ValidationError({"file": "No file provided."})
        if not iv or len(iv) < 16:
            raise serializers.ValidationError({"iv": "Invalid IV. Must be at least 16 chars."})

        file_type = get_file_category(file.name)
        if file_type == 'invalid':
            raise serializers.ValidationError({'file_type': 'Unsupported file type.'})

        attrs['file_type'] = file_type

        file_name = clean_filename(file.name)
        capsoul_media = time_capsoul.timecapsoul_media_files.all()
        keys = capsoul_media.values_list('s3_key', flat = True)
        name =[k.split('/')[-1] for k in keys ]
        if name:
            unique_file_name = generate_unique_file_name(existing_file_name=name, base_name= file_name)
            attrs['unique_file_name'] = unique_file_name
        else:
            attrs['unique_file_name'] = file_name

        file.name = file_name
        attrs['title'] = file_name

        max_file_size = settings.DATA_UPLOAD_MAX_MEMORY_SIZE
        if file.size > max_file_size:
            raise serializers.ValidationError({
                "file": f"File size exceeds max limit of {max_file_size} bytes"
            })
        return attrs


    def create(self, validated_data):
        user = self.context['user']
        time_capsoul = self.context['time_capsoul']
        progress_callback = self.context.get('progress_callback')
        
        if progress_callback:
            progress_callback(5, "Initializing upload...")

        file = validated_data.pop('file')
        # file_name = file.name
        iv = validated_data.pop('iv')
        file_type = validated_data.get('file_type')
        file_name = validated_data.pop('unique_file_name')

        validated_data['user'] = user
        validated_data['time_capsoul'] = time_capsoul

        if progress_callback:
            progress_callback(10, "Initializing upload...")
        
        try:
            s3_key = generate_capsoul_media_s3_key(file_name, user.s3_storage_id, time_capsoul.id)
            result = media_uploader(
                file_type = file_type,
                key=s3_key,
                encrypted_file=file,
                iv_str=iv,
                # content_type="audio/mpeg",
                progress_callback=progress_callback,
                file_ext=os.path.splitext(file.name)[1].lower(),
            )
            # result = decrypt_upload_and_extract_audio_thumbnail_chunked(
            #     file_type = file_type,
            #     key=s3_key,
            #     encrypted_file=file,
            #     iv_str=iv,
            #     # content_type="audio/mpeg",
            #     progress_callback=upload_progress_callback,
            #     file_ext=os.path.splitext(file.name)[1].lower(),
            # )
        except Exception as e:
            logger.error('Chunked Decrypt/Upload Error', exc_info=True)
            # if progress_callback:
            #     progress_callback(0, f"Chunked decryption/upload failed: {str(e)}")
            raise serializers.ValidationError({'upload_error': f"Chunked decryption/upload failed: {str(e)}"})

        if progress_callback:
            progress_callback(86, "File uploaded successfully, generating thumbnails...")

        validated_data['title'] = file_name
        validated_data['file_type'] = file_type
        validated_data['s3_key'] = s3_key
        validated_data['file_size'] = get_readable_file_size_from_bytes(result['uploaded_size'])
        

        if progress_callback:
            progress_callback(87, "Generating thumbnails...")

        try:
            if  result.get('thumbnail_data'):
                from django.core.files.base import ContentFile
                image_file = ContentFile(result['thumbnail_data'], name=f"thumbnail_{file.name}.jpg")

                if image_file:
                    from userauth.models import Assets
                    asset = Assets.objects.create(image=image_file, asset_types='TimeCapsoul/Thubmnail/Audio')
                    validated_data['thumbnail'] = asset
        except Exception as e:
            logger.exception('Exception while extracting thumbnail')

        if progress_callback:
            progress_callback(88, "Finalizing...")

        instance = super().create(validated_data)

        if progress_callback:
            progress_callback(90, "File processed successfully!")

        return instance



def generate_signature(s3_key: str, exp: int) -> str:
    """
    Generate base64-encoded HMAC signature for s3_key and expiry.
    """
    raw = f"{s3_key}:{exp}"
    sig = hmac.new(settings.SECRET_KEY.encode(), raw.encode(), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(sig).decode().rstrip("=")




class TimeCapSoulMediaFileReadOnlySerializer(serializers.ModelSerializer):
    thumbnail = AssetSerializer()
    s3_url = serializers.SerializerMethodField()
    # list_view_url = serializers.SerializerMethodField()
    # title = serializers.SerializerMethodField()
    class Meta:
        model = TimeCapSoulMediaFile
        fields = ('id', 'is_cover_image', 'created_at', 'updated_at','file_size', 'file_type', 's3_url', 'title', 'description', 'thumbnail')

    # def get_s3_url(self, obj):
    #     import time
    #     exp = int(time.time()) + settings.DECRYPT_LINK_TTL_SECONDS 
    #     s3_key = obj.s3_key 
    #     sig = generate_signature(s3_key, exp)

    #     served_key = s3_key[37:]
    #     if served_key.lower().endswith(".doc"):
    #         served_key = served_key[:-4] + ".docx"  # change extension

    #     return f"/api/v0/time-capsoul/api/media/time-capsoul/{obj.id}/serve/{served_key}/?exp={exp}&sig={sig}"
    
    def get_s3_url(self, obj):

        # --- Compute expiry ---
        exp = int(time.time()) + settings.DECRYPT_LINK_TTL_SECONDS
        s3_key = obj.s3_key
        cache_key = f"time_capsoul_media{obj.id}"

        # --- Try fetching from cache ---
        cached_url = cache.get(cache_key)
        if cached_url:
            return cached_url

        # --- Generate fresh signed URL ---
        sig = generate_signature(s3_key, exp)

        # Handle .doc → .docx extension
        served_key = s3_key[37:]
        if served_key.lower().endswith(".doc"):
            served_key = served_key[:-4] + ".docx"

        # Build URL
        url = f"/api/v0/time-capsoul/api/media/time-capsoul/{obj.id}/serve/{served_key}/?exp={exp}&sig={sig}"

        # --- Cache the URL until just before it expires ---
        now = int(time.time())
        ttl = max(0, exp - now - 5)  # expire 5s before real expiration
        if ttl > 0:
            cache.set(cache_key, url, timeout=ttl)

        return url

    
    # def get_list_view_url(self, obj):
    #     s3_key = obj.s3_key 
    #     served_key = s3_key[37:]
    #     if served_key.lower().endswith(".doc"):
    #         served_key = served_key[:-4] + ".docx"  # change extension

    #     return f"/api/v0/time-capsoul/api/media-id/{obj.id}/{served_key}/"
    

class TimeCapSoulMediaFilesReadOnlySerailizer(serializers.ModelSerializer):
    time_capsoul = TimeCapSoulSerializer()
    media_files = TimeCapSoulMediaFileReadOnlySerializer(many=True)

    class Meta:
        model = TimeCapSoulDetail
        fields = ('time_capsoul', 'media_files')


class TimeCapsoulMediaFileUpdationSerializer(serializers.ModelSerializer):
    set_as_cover = serializers.CharField(required = False)

    class Meta:
        model = TimeCapSoulMediaFile
        fields = ('description', 'title',  'set_as_cover')

    def update(self, instance, validated_data):
        current_user = self.context.get('current_user')
        media_file = instance
        user = instance.user
        time_capsoul  = instance.time_capsoul
        set_as_cover = validated_data.pop('set_as_cover', None)
        cover_image =  time_capsoul.capsoul_template.cover_image
        title = validated_data.get('title', instance.title)
        description = validated_data.get('description', instance.description)
        file_extension = f'.{instance.s3_key.split('/')[-1].split('.')[-1]}'
        
        if not str(title).endswith(f'{file_extension}'): 
            title = f'{title}{file_extension}'

        if time_capsoul.status == 'unlocked':
            is_cover_image = False
            if  time_capsoul.capsoul_template.default_template is None and bool(set_as_cover) == True and  media_file.is_cover_image == False and media_file.file_type == "image":
                from userauth.models import Assets
                media_s3_key =  str(media_file.s3_key)
                cover_image = Assets.objects.create(s3_key=media_s3_key)
                
                # file_name = media_s3_key.split('/')[-1]
                # file_bytes, content_type = get_media_file_bytes_with_content_type(media_file, user)
                # if not file_bytes or not content_type:
                #     raise serializers.ValidationError({'detail': "Media file not found on s3"})
                            
                # here uploading plain file  without any encryption to s3 with public access
                # s3_key, url = save_and_upload_decrypted_file(filename=file_name, decrypted_bytes=file_bytes, bucket='time-capsoul-files', content_type=content_type)
                # cover_image = Assets.objects.create(s3_key = s3_key)
                is_cover_image = True
                other_media = TimeCapSoulMediaFile.objects.filter(time_capsoul = time_capsoul, is_deleted=False, user = user).exclude(id = media_file.id)
                other_media.update(is_cover_image = False)
                
            replica_instance = create_time_capsoul(
                old_time_capsoul = time_capsoul, # create time-capsoul replica
                current_user = current_user,
                option_type = 'replica_creation',
                cover_image = cover_image 
            )
            if current_user == time_capsoul.user: # if user is owner of the capsoul
                parent_media_files = TimeCapSoulMediaFile.objects.filter(time_capsoul = time_capsoul, is_deleted = False)
            else:
                recipient = TimeCapSoulRecipient.objects.filter(time_capsoul = time_capsoul, email = current_user.email).first()
                if not recipient:
                    logger.info(f"Recipient not found for tagged capsoul for {time_capsoul.id} and user {user.email}")
                    raise serializers.ValidationError({'detail': 'You do not have access to this time-capsoul.'})
                else:
                    parent_files_id = get_recipient_capsoul_ids(recipient)
                    parent_media_files = TimeCapSoulMediaFile.objects.filter(
                        time_capsoul=time_capsoul,
                        id__in = parent_files_id,
                    )
            new_media_count = 0
            old_media_count = parent_media_files.count()   
            for parent_file in parent_media_files:
                try:
                    if parent_file.id == instance.id:
                        is_media_created = create_time_capsoul_media_file(
                            old_media=parent_file,
                            new_capsoul=replica_instance,
                            current_user = current_user,
                            option_type = 'replica_creation',
                            updated_media_title=title,
                            updated_media_description=description
                        )
                    else:
                        is_media_created = create_time_capsoul_media_file(
                            old_media=parent_file,
                            new_capsoul=replica_instance,
                            current_user = current_user,
                            option_type = 'replica_creation',
                        )
                except Exception as e:
                    logger.exception(F'Exception while creating time-capsoul media-file replica for media-file id {parent_file.id} and user {user.email}')
                    pass
                else:
                    if is_media_created:
                        new_media_count += 1
            print(f"Old media count: {old_media_count}, New media count: {new_media_count}")
            return instance

            
        else:
            if current_user != time_capsoul.user:
                raise serializers.ValidationError({'user': "Dont have permission to perform that action"})
            
            title =  title
            description = description
            
            if title:
                instance.title = title
            if description:
                instance.description = description
            
            if time_capsoul.capsoul_template.default_template is None:
                    
                if  bool(set_as_cover) == True and  instance.is_cover_image == False and media_file.file_type == "image":
                    if time_capsoul.capsoul_template.default_template is None:
                        from userauth.models import Assets
                        media_s3_key =  str(media_file.s3_key)
                        # file_name = media_s3_key.split('/')[-1]
                        # cover_s3_key = f'{media_s3_key[0:62]}cover/{file_name}'
                        assets_obj = Assets.objects.create(s3_key=media_s3_key)

                            
                            # file_bytes, content_type = get_media_file_bytes_with_content_type(media_file, current_user)
                            # if not file_bytes or not content_type:
                            #     logger.error(f'Media file decryption failed while set as cover media-id: {media_file.id} for user {current_user.email}')
                            #     raise serializers.ValidationError({'file': 'media file decryption failed'})
                            # s3_key, url = save_and_upload_decrypted_file(filename=file_name, decrypted_bytes=file_bytes, bucket='time-capsoul-files', content_type=content_type, s3_key=cover_s3_key)
                        custom_template = time_capsoul.capsoul_template 
                        custom_template.cover_image = assets_obj
                        custom_template.save()
                        instance.is_cover_image = True
                        other_media = TimeCapSoulMediaFile.objects.filter(time_capsoul = time_capsoul, is_deleted=False, user = user).exclude(id = media_file.id)
                        other_media.update(is_cover_image = False)
            instance.save()
        return instance


class TimeCapsoulUnlockSerializer(serializers.ModelSerializer):
    unlock_date = serializers.DateTimeField(required=True)

    class Meta:
        model = TimeCapSoul
        fields = ('unlock_date',)

    def validate(self, attrs):
        unlock_date = attrs.get('unlock_date')
        instance = self.instance 

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
        time_capsoul = instance
        if time_capsoul.status == 'created':
            capsoul_recipients = TimeCapSoulRecipient.objects.filter(
                time_capsoul=time_capsoul,
                is_capsoul_deleted = False
            )

            if  capsoul_recipients.count() < 1:
                raise serializers.ValidationError({'recipients': 'No recipients added'})
           
            instance.unlock_date = validated_data['unlock_date']
            instance.status = 'sealed'
            instance.is_locked = True
            instance.save()
            unlock_time = instance.unlock_date
            from datetime import timedelta
            from django.utils import timezone

            now = timezone.now()
            if now <= instance.unlock_date <= now + timedelta(hours=1):
                capsoul_almost_unlock.apply_async((time_capsoul.id,),eta=instance.unlock_date)
                # capsoul_unlocked.apply_async((time_capsoul.id,), eta=instance.unlock_date)
           
            
            # create notification at sealed of owner
            notif = NotificationService.create_notification_with_key(
                notification_key='capsoul_sealed',
                user=time_capsoul.user,
                time_capsoul=time_capsoul
            )
            
            # send email here tagged 
            time_cap_owner = time_capsoul.user.first_name if time_capsoul.user.first_name else time_capsoul.user.email
            try:
                capsoul_media_ids = list(time_capsoul.timecapsoul_media_files.filter( is_deleted=False).values_list('id', flat=True))


                if capsoul_recipients:
                    
                    for recipient in capsoul_recipients:
                        person_name = recipient.name
                        person_email = recipient.email
                        recipient.parent_media_refrences = capsoul_media_ids
                        recipient.save()
                        
                        # create notification at invited for tagged user if exists
                        try:
                            user = User.objects.get(email = person_email)
                        except User.DoesNotExist as e:
                            # skip if user not exists
                            pass
                        else:
                            notification_msg = f"You’ve been invited to a capsoul. {time_cap_owner} special has saved a memory with you in mind — a surprise awaits."
                            notif = NotificationService.create_notification_with_key(
                                notification_key='capsoul_invite_received',
                                user=user,
                                time_capsoul=time_capsoul,
                                custom_message=notification_msg
                            )
                        try: # sending email using celery task
                            send_html_email_task.apply_async(
                                kwargs={
                                    "subject": "You’ve received a Time Capsoul sealed with love.",
                                    "to_email": person_email,
                                    "template_name": "userauth/time_capsoul_tagged.html",
                                    "context": {
                                        "user": person_name,
                                        "sender_name": time_cap_owner,
                                        "unlock_date": instance.unlock_date
                                    }
                                }
                            )
                        except Exception as e:
                            print(f'Exception as {e}')
                        
            except Exception as e:
                pass
            instance.save()
        return instance


class TimeCapSoulRecipientSerializer(serializers.ModelSerializer):
    class Meta:
        model = TimeCapSoulRecipient
        fields = ['id', 'is_opened', 'name', 'email']


class RecipientsDetailSerializer(serializers.ModelSerializer):
    recipients = TimeCapSoulRecipientSerializer(many=True)


    class Meta:
        model = TimeCapSoulRecipient
        fields = ['id', 'recipients']  

    def create(self, validated_data):
        time_capsoul = self.context.get('time_capsoul')
        if not time_capsoul:
            raise serializers.ValidationError("TimeCapsoul context is required.")

        recipients_data = validated_data.pop('recipients', [])

        for recipient_data in recipients_data:
            name = recipient_data['name']
            email  = recipient_data['email']
            try:
                recipient = TimeCapSoulRecipient.objects.get(email=email, time_capsoul= time_capsoul)
            except TimeCapSoulRecipient.DoesNotExist:
                recipient = TimeCapSoulRecipient.objects.create(name=name, email=email, time_capsoul= time_capsoul)
        
        return recipient


    # def update(self, instance, validated_data):
    #     recipients_data = validated_data.pop('recipients', None)

    #     if recipients_data is not None:
    #         instance.recipients.clear()
    #         for recipient_data in recipients_data:
    #             recipient, _ = TimeCapSoulRecipient.objects.get_or_create(**recipient_data)
    #             instance.recipients.add(recipient)

    #     return instance
