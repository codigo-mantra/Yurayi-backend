import os
from django.utils import timezone
from userauth.models import Assets
from django.conf import settings
import base64, hmac, hashlib
from datetime import datetime, timedelta
from django.shortcuts import get_object_or_404
from userauth.models import User


from django.core.files.images import ImageFile 
from timecapsoul.utils import MediaThumbnailExtractor
from memory_room.apis.serializers.memory_room import AssetSerializer
from memory_room.models import (
    TimeCapSoulTemplateDefault,CustomTimeCapSoulTemplate,TimeCapSoul,TimeCapSoulRecipient,RecipientsDetail,
    TimeCapSoulMediaFile,TimeCapSoulDetail, TimeCapSoulMediaFileReplica, TimeCapSoulReplica,
    )
from timecapsoul.utils import send_html_email
from memory_room.crypto_utils import generate_signature
from memory_room.crypto_utils import encrypt_and_upload_file, decrypt_and_get_image, generate_signed_path, decrypt_frontend_file,save_and_upload_decrypted_file, encrypt_and_upload_file_no_iv
from memory_room.utils import upload_file_to_s3_bucket, get_file_category,get_readable_file_size_from_bytes, S3FileHandler

from userauth.tasks import send_html_email_task
from rest_framework import serializers
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

        custom = CustomTimeCapSoulTemplate.objects.create(
            name=default.name, slug=default.slug, summary=default.summary,
            cover_image=default.cover_image, default_template=default
        )
        logger.info('Time-capsoul Custom Template created', extra={"template_id": custom.id})
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
        capsoul_recipients = TimeCapSoulRecipient.objects.filter(time_capsoul = obj)
        serializer = TimeCapSoulRecipientSerializer(capsoul_recipients, many=True)
        return serializer.data

    def get_is_owner(self, obj):
        user = self.context.get('user', None)  
        if user:
            if obj.user == user:
                return True
        return False

    def get_total_files(self, obj):
        try:
            detail = obj.details
            return detail.media_files.count()
        except TimeCapSoulDetail.DoesNotExist:
            return 0
        except AttributeError:
            return 0


    def get_status(self, obj):
        if obj.status == 'sealed':
            current_datetime = timezone.now()  
            unlock_date = obj.details.unlock_date
            if unlock_date and current_datetime > unlock_date:
                obj.status = 'unlocked'
                obj.save()
        return obj.get_status_display()

    def get_is_default_template(self, obj):
        return bool(getattr(obj.capsoul_template, "default_template", False))

    def get_unlocked_data(self, obj):
        details = getattr(obj, 'details', None)
        if not details:
            return None
        return {
            "is_locked": details.is_locked,
            "unlock_date": details.unlock_date,
        }

    def get_name(self, obj):
        return getattr(obj.capsoul_template, "name", None)

    def get_summary(self, obj):
        return getattr(obj.capsoul_template, "summary", None)

    def get_cover_image(self, obj):
        cover_image = getattr(obj.capsoul_template, "cover_image", None)
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
            try:
                replica_instance = TimeCapSoul.objects.get(capsoul_replica_refrence = time_capsoul)
            except TimeCapSoul.DoesNotExist as e:
                # create custom template for replica
                template = CustomTimeCapSoulTemplate.objects.create(
                    name = name + '(1)',
                    summary = summary,
                    cover_image = cover_image,
                    default_template = time_capsoul.capsoul_template.default_template
                )
                template.slug = generate_unique_slug(template)
                replica_instance = TimeCapSoul.objects.create(
                                                            user = user,
                                                            capsoul_template=template,
                                                            status = 'created',
                                                            capsoul_replica_refrence = time_capsoul
                                                            )
                
            template = replica_instance.capsoul_template
            template.name = name
            template.summary = summary
            template.cover_image = cover_image
            template.slug = generate_unique_slug(template)
            template.save()
            replica_instance.save()
            return instance
            


        else:
            if instance.capsoul_template.default_template is None: # create from scratch
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


    # def create(self, validated_data):
    #     user = self.context['user']
    #     file = validated_data.pop('file', None)
    #     iv = validated_data.pop('iv')
    #     time_capsoul = self.context['time_capsoul']
    #     validated_data['user'] = user
    #     # validated_data['time_capsoul'] = time_capsoul

    #     if time_capsoul.status == 'unlocked':

    #         try: # get or create time-capsoul replica here
    #             time_capsoul_replica = TimeCapSoul.objects.get(capsoul_replica_refrence = time_capsoul)
    #         except TimeCapSoul.DoesNotExist as e:
    #             # create custom template for replica
    #             template = time_capsoul.capsoul_template
    #             template_replica = CustomTimeCapSoulTemplate.objects.create(
    #                 name = template.name,
    #                 summary = template.summary,
    #                 cover_image = template.cover_image,
    #                 default_template = time_capsoul.capsoul_template.default_template
    #             )
    #             template_replica.slug = generate_unique_slug(template_replica)
    #             time_capsoul_replica = TimeCapSoul.objects.create(
    #                                                         user = user,
    #                                                         capsoul_template=template_replica,
    #                                                         status = 'created',
    #                                                         capsoul_replica_refrence = time_capsoul)
    #         finally:
    #             validated_data['time_capsoul'] = time_capsoul_replica
    #     else:
    #         validated_data['time_capsoul'] = time_capsoul

      
    #     if not file:
    #         raise serializers.ValidationError({"file": "No file provided."})
        
    #     try:
    #         #Decrypt using shared AES key + IV
    #         decrypted_bytes = decrypt_frontend_file(file, iv)
    #     except Exception as e:
    #         raise serializers.ValidationError({'decryption_error': f'File decryption failed: {str(e)}'})
        
    #     file_type = get_file_category(file.name)
    #     if file_type == 'invalid':
    #         raise serializers.ValidationError({'file_type': 'File type is invalid.'})



    #     if file:
    #         validated_data['file_size'] = get_readable_file_size_from_bytes(len(decrypted_bytes))
    #         s3_key = f"{user.s3_storage_id}/time-capsoul-files/{file.name}"
    #         s3_key = s3_key.replace(" ", "_") # remove white spaces

    #         try:
    #             # Upload decrypted file
    #             upload_media_obj = encrypt_and_upload_file(
    #                 key=s3_key,
    #                 plaintext_bytes=decrypted_bytes,
    #                 content_type=file.content_type,
    #                 file_category=file_type
    #             )
    #         except Exception as e:
    #             print(f'[Upload Error] {e}')
    #             raise serializers.ValidationError({'upload_error': "File upload failed. Invalid file."})

            
    #         validated_data['title'] = file.name
    #         validated_data['file_type'] = file_type
    #         validated_data['s3_key'] = s3_key
    #         validated_data['file'] = file

    #         # Set the file field 
    #         if file_type == 'audio':
    #             try:
    #                 # Extract thumbnail 
    #                 try:
    #                     ext = os.path.splitext(file.name)[1]
    #                     extractor = MediaThumbnailExtractor(file, ext)
    #                     thumbnail_data = extractor.extract_audio_thumbnail_from_bytes(decrypted_bytes = decrypted_bytes, extension=ext )

    #                 except Exception as e:
    #                     print(f'Exception while media thumbnail extraction: {e}')
    #                 else:
    #                     if thumbnail_data:
    #                         from django.core.files.base import ContentFile
    #                         from userauth.models import Assets 

    #                         image_file = ContentFile(thumbnail_data, name=f"thumbnail_{file.name}.jpg")
    #                         asset = Assets.objects.create(image=image_file, asset_types='TimeCapsoul/Thubmnail/Audio')
    #                         validated_data['thumbnail'] = asset
    #             except Exception as e:
    #                 print(f'\n Exception while extracting thumbnail: \n{e}')
    #     return super().create(validated_data)
    
    
    
    
    def create(self, validated_data):
        current_date = timezone.localtime(timezone.now())
        user = self.context['user']
        file = validated_data.pop('file', None)
        iv = validated_data.pop('iv')
        time_capsoul = self.context['time_capsoul']
        progress_callback = self.context.get('progress_callback')

        validated_data['user'] = user

        if time_capsoul.status == 'unlocked':
            try:  # get or create time-capsoul replica here
                time_capsoul_replica = TimeCapSoul.objects.get(capsoul_replica_refrence=time_capsoul)
            except TimeCapSoul.DoesNotExist as e:
                template = time_capsoul.capsoul_template
                template_replica = CustomTimeCapSoulTemplate.objects.create(
                    name=template.name,
                    summary=template.summary,
                    cover_image=template.cover_image,
                    default_template=time_capsoul.capsoul_template.default_template,
                    created_at = current_date
                )
                template_replica.slug = generate_unique_slug(template_replica)
                time_capsoul_replica = TimeCapSoul.objects.create(
                    user=user,
                    capsoul_template=template_replica,
                    status='created',
                    capsoul_replica_refrence=time_capsoul,
                    created_at = current_date
                )
            finally:
                validated_data['time_capsoul'] = time_capsoul_replica
        else:
            validated_data['time_capsoul'] = time_capsoul

        if not file:
            raise serializers.ValidationError({"file": "No file provided."})

        # === Progress: starting decryption ===
        if progress_callback:
            progress_callback(5, "Starting file processing...")

        try:
            if progress_callback:
                progress_callback(10, "Decrypting file...")
            decrypted_bytes = decrypt_frontend_file(file, iv)
            if progress_callback:
                progress_callback(20, "File decrypted successfully")
        except Exception as e:
            if progress_callback:
                progress_callback(-1, f"Decryption failed: {str(e)}")
            raise serializers.ValidationError({'decryption_error': f'File decryption failed: {str(e)}'})

        if progress_callback:
            progress_callback(25, "Validating file type...")

        file_type = get_file_category(file.name)
        if file_type == 'invalid':
            if progress_callback:
                progress_callback(-1, "Invalid file type")
            raise serializers.ValidationError({'file_type': 'File type is invalid.'})

        validated_data['file_size'] = get_readable_file_size_from_bytes(len(decrypted_bytes))
        s3_key = f"{user.s3_storage_id}/time-capsoul-files/{file.name}"
        s3_key = s3_key.replace(" ", "_")  # remove white spaces

        if progress_callback:
            progress_callback(30, "Preparing for upload...")

        try:
            # Create progress wrapper for upload (map upload 0-100 → overall 30-80)
            def upload_progress_callback(upload_percentage, message):
                if progress_callback:
                    if upload_percentage == -1:
                        progress_callback(-1, message)
                    else:
                        overall_progress = 30 + int((upload_percentage / 100) * 50)
                        progress_callback(min(overall_progress, 80), message)

            upload_media_obj = encrypt_and_upload_file(
                key=s3_key,
                plaintext_bytes=decrypted_bytes,
                content_type=file.content_type,
                file_category=file_type,
                progress_callback=upload_progress_callback
            )
        except Exception as e:
            logger.error('Upload Error', extra={"error": str(e)})
            if progress_callback:
                progress_callback(-1, f"Upload failed: {str(e)}")
            raise serializers.ValidationError({'upload_error': "File upload failed. Invalid file."})

        validated_data['title'] = file.name
        validated_data['file_type'] = file_type
        validated_data['s3_key'] = s3_key
        validated_data['file'] = file

        if progress_callback:
            progress_callback(85, "Generating thumbnails...")

        # === Thumbnail generation (only audio for now) ===
        try:
            if file_type == 'audio':
                try:
                    ext = os.path.splitext(file.name)[1]
                    extractor = MediaThumbnailExtractor(file, ext)
                    thumbnail_data = extractor.extract_audio_thumbnail_from_bytes(
                        decrypted_bytes=decrypted_bytes, extension=ext
                    )
                except Exception as e:
                    logger.exception('Exception while media thumbnail extraction')
                else:
                    if thumbnail_data:
                        from django.core.files.base import ContentFile
                        from userauth.models import Assets

                        image_file = ContentFile(thumbnail_data, name=f"thumbnail_{file.name}.jpg")
                        asset = Assets.objects.create(image=image_file, asset_types='TimeCapsoul/Thubmnail/Audio')
                        validated_data['thumbnail'] = asset
        except Exception as e:
            logger.exception('Exception while extracting thumbnail')

        if progress_callback:
            progress_callback(95, "Finalizing...")

        instance = super().create(validated_data)

        if progress_callback:
            progress_callback(100, "File processed successfully!")

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
    class Meta:
        model = TimeCapSoulMediaFile
        fields = ('id', 'is_cover_image', 'created_at', 'updated_at','file_size', 'file_type', 's3_url', 'title', 'description', 'thumbnail')

    def get_s3_url(self, obj):
        import time, base64, hmac, hashlib

        exp = int(time.time()) + 60 * 5  
        s3_key = obj.s3_key 
        sig = generate_signature(s3_key, exp)
        return f"/api/v0/time-capsoul/api/media/time-capsoul/{obj.id}/serve/{s3_key[37:]}/?exp={exp}&sig={sig}"


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
        media_file = instance
        user = instance.user
        time_capsoul  = instance.time_capsoul
        set_as_cover = validated_data.pop('set_as_cover', None)
        
        if time_capsoul.status == 'unlocked':
            created_at = timezone.localtime(timezone.now())
            

            try: # get or create time-capsoul replica here

                time_capsoul_replica = TimeCapSoul.objects.get(capsoul_replica_refrence = time_capsoul)
            except TimeCapSoul.DoesNotExist as e:
                # create custom template for replica
                template = time_capsoul.capsoul_template
                template_replica = CustomTimeCapSoulTemplate.objects.create(
                    name = template.name + '(1)',
                    summary = template.summary,
                    cover_image = template.cover_image,
                    default_template = time_capsoul.capsoul_template.default_template,
                    created_at = created_at
                )
                template_replica.slug = generate_unique_slug(template_replica)
                time_capsoul_replica = TimeCapSoul.objects.create(
                                                            user = user,
                                                            capsoul_template=template_replica,
                                                            status = 'created',
                                                            created_at = created_at,
                                                            capsoul_replica_refrence = time_capsoul)
            
            # now create get or create media-file replica here
            try:
                media_file_replica = TimeCapSoulMediaFile.objects.get(time_capsoul=time_capsoul_replica, media_refrence_replica = instance)
            except TimeCapSoulMediaFile.DoesNotExist:
                is_cover_image = False
                title = validated_data.get('title', instance.title)
                description = validated_data.get('description', instance.description)
                
                if  bool(set_as_cover) == True and  media_file.is_cover_image == False and media_file.file_type == "image":
                    if time_capsoul_replica.capsoul_template.default_template is None:
                        from userauth.models import Assets
                        # here upload file to s3 bucket with kms encryption
                        media_s3_key =  str(media_file.s3_key)
                        file_name = media_s3_key.split('/')[-1]
                        try:
                            file_bytes,content_type = decrypt_and_get_image(media_s3_key)
                        except Exception as e:
                            print(f'Exception while media file decryption as {e}')
                        else:
                            # here uploading plain file  without any encryption to s3 with public access
                            s3_key, url = save_and_upload_decrypted_file(filename=file_name, decrypted_bytes=file_bytes, bucket='time-capsoul-files', content_type=content_type)
                            assets_obj = Assets.objects.create(image = media_file.file, s3_key = s3_key, s3_url = url)
                            template = time_capsoul_replica.capsoul_template
                            template.cover_image = assets_obj
                            template.save() # save template
                            is_cover_image =True
                                    
                media_file_replica = TimeCapSoulMediaFile.objects.create(
                    user = user,
                    time_capsoul = time_capsoul_replica,
                    media_refrence_replica = instance,
                    s3_key = media_file.s3_key,
                    file_type = media_file.file_type,
                    title = title + '(1)',
                    description = description,
                    file_size  = media_file.file_size,
                    thumbnail = media_file.thumbnail,
                    is_cover_image = is_cover_image,
                    created_at = created_at
                )
            except Exception as e:
                logger.exception('Exception while creating time-capsoul replica')
                pass 
            
            else:
                if  bool(set_as_cover) == True and  media_file_replica.is_cover_image == False and media_file_replica.file_type == "image":
                    if time_capsoul_replica.capsoul_template.default_template is None:
                                from userauth.models import Assets
                                # here upload file to s3 bucket with kms encryption
                                media_s3_key =  str(media_file.s3_key)
                                file_name = media_s3_key.split('/')[-1]
                                try:
                                    file_bytes,content_type = decrypt_and_get_image(media_s3_key)
                                except Exception as e:
                                    logger.exception('Exception while media file decryption')
                                except Exception as e:
                                    logger.exception('Exception while media file decryption')
                                else:
                                    # here uploading plain file  without any encryption to s3 with public access
                                    s3_key, url = save_and_upload_decrypted_file(filename=file_name, decrypted_bytes=file_bytes, bucket='time-capsoul-files', content_type=content_type)
                                    assets_obj = Assets.objects.create(image = media_file.file, s3_key = s3_key, s3_url = url)
                                    template = time_capsoul_replica.capsoul_template
                                    template.cover_image = assets_obj
                                    template.save() # save template
                                    media_file_replica.is_cover_image =True
                                    media_file_replica.save() # save replica media file
                else:
                    title = validated_data.get('title', None)
                    description = validated_data.get('description', None)
                    if title:
                        media_file_replica.title = title
                    if description:
                        media_file_replica.description = description
                        
                    media_file_replica.save() # save replica media file
            return instance
        else:
            title =  validated_data.get('title', None)
            description = validated_data.get('description', None)
            
            if title:
                instance.title = title
            if description:
                instance.description = description
                
            if  bool(set_as_cover) == True and  instance.is_cover_image == False and media_file.file_type == "image":
                if time_capsoul.capsoul_template.default_template is None:
                    from userauth.models import Assets
                    media_s3_key =  str(media_file.s3_key)
                    file_name = media_s3_key.split('/')[-1]
                    file_bytes,content_type = decrypt_and_get_image(media_s3_key)
                    s3_key, url = save_and_upload_decrypted_file(filename=file_name, decrypted_bytes=file_bytes, bucket='time-capsoul-files', content_type=content_type)
                    assets_obj = Assets.objects.create(image = media_file.file, s3_url=url, s3_key=s3_key)
                    custom_template = time_capsoul.capsoul_template 
                    custom_template.cover_image = assets_obj
                    custom_template.save()
                    instance.is_cover_image = True
            instance.save()
        return instance


class TimeCapsoulUnlockSerializer(serializers.ModelSerializer):
    unlock_date = serializers.DateTimeField(required=True)

    class Meta:
        model = TimeCapSoulDetail
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
        time_capsoul = instance.time_capsoul
        if time_capsoul.status == 'created':
            capsoul_recipients = TimeCapSoulRecipient.objects.filter(
                time_capsoul=instance.time_capsoul
            )

            if  capsoul_recipients.count() < 1:
                raise serializers.ValidationError({'recipients': 'No recipients added'})
           
            instance.unlock_date = validated_data['unlock_date']
            time_capsoul.status = 'sealed'
            instance.is_locked = True
            time_capsoul.save()
            unlock_time = instance.unlock_date
           
            # # CAPSOUL_ALMOST_UNLOCK → exactly at unlock time
            # capsoul_almost_unlock.apply_async((instance.id,), eta=unlock_time)

            # # CAPSOUL_UNLOCKED → exactly at unlock time
            # capsoul_unlocked.apply_async((instance.id,), eta=unlock_time)

            # # CAPSOUL_WAITING → 24 hours after unlock
            # capsoul_waiting.apply_async((instance.id,), eta=unlock_time + timedelta(hours=24))

            # # CAPSOUL_REMINDER_7_DAYS → 7 days after unlock
            # capsoul_reminder_7_days.apply_async((instance.id,), eta=unlock_time + timedelta(days=7))
            
            # # CAPSOUL_MEMORY_ONE_YEAR_AGO → at unlock time (owner)
            # capsoul_memory_one_year_ago.apply_async((instance.id,), eta=unlock_time + timedelta(days=364))

            
            
            # create notification at sealed of owner
            notif = NotificationService.create_notification_with_key(
                notification_key='capsoul_sealed',
                user=time_capsoul.user,
                time_capsoul=time_capsoul
            )
            
            # send email here tagged 
            time_cap_owner = instance.time_capsoul.user.first_name if instance.time_capsoul.user.first_name else instance.time_capsoul.user.email
            try:
                if capsoul_recipients:
                    tagged_recipients = capsoul_recipients.values_list("name", "email")

                    
                    for recipient in tagged_recipients:
                        person_name = recipient[0]
                        person_email = recipient[-1]
                        
                        # create notification at invited for tagged user if exists
                        try:
                            user = User.objects.get(email = person_email)
                        except User.DoesNotExist as e:
                            # skip if user not exists
                            pass
                        else:
                            notif = NotificationService.create_notification_with_key(
                                notification_key='capsoul_invite_received',
                                user=user,
                                time_capsoul=time_capsoul
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

            recipient, _ = TimeCapSoulRecipient.objects.get_or_create(name=name, email=email, time_capsoul= time_capsoul)
        
        return recipient


    # def update(self, instance, validated_data):
    #     recipients_data = validated_data.pop('recipients', None)

    #     if recipients_data is not None:
    #         instance.recipients.clear()
    #         for recipient_data in recipients_data:
    #             recipient, _ = TimeCapSoulRecipient.objects.get_or_create(**recipient_data)
    #             instance.recipients.add(recipient)

    #     return instance
