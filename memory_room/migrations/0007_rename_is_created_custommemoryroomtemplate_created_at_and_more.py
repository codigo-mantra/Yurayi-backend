# Generated by Django 5.2.4 on 2025-07-21 08:02

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('memory_room', '0006_memoryroommediafile_s3_key_and_more'),
    ]

    operations = [
        migrations.RenameField(
            model_name='custommemoryroomtemplate',
            old_name='is_created',
            new_name='created_at',
        ),
        migrations.RenameField(
            model_name='customtimecapsoultemplate',
            old_name='is_created',
            new_name='created_at',
        ),
        migrations.RenameField(
            model_name='memoryroom',
            old_name='is_created',
            new_name='created_at',
        ),
        migrations.RenameField(
            model_name='memoryroomdetail',
            old_name='is_created',
            new_name='created_at',
        ),
        migrations.RenameField(
            model_name='memoryroommediafile',
            old_name='is_created',
            new_name='created_at',
        ),
        migrations.RenameField(
            model_name='memoryroomtemplatedefault',
            old_name='is_created',
            new_name='created_at',
        ),
        migrations.RenameField(
            model_name='recipientsdetail',
            old_name='is_created',
            new_name='created_at',
        ),
        migrations.RenameField(
            model_name='timecapsoul',
            old_name='is_created',
            new_name='created_at',
        ),
        migrations.RenameField(
            model_name='timecapsouldetail',
            old_name='is_created',
            new_name='created_at',
        ),
        migrations.RenameField(
            model_name='timecapsoulmediafile',
            old_name='is_created',
            new_name='created_at',
        ),
        migrations.RenameField(
            model_name='timecapsoulrecipient',
            old_name='is_created',
            new_name='created_at',
        ),
        migrations.RenameField(
            model_name='timecapsoultemplatedefault',
            old_name='is_created',
            new_name='created_at',
        ),
        migrations.RenameField(
            model_name='usermapper',
            old_name='is_created',
            new_name='created_at',
        ),
        migrations.AddField(
            model_name='timecapsoul',
            name='status',
            field=models.CharField(choices=[('sealed', 'Sealed With Love'), ('unlocked', 'Unlocked'), ('created', 'Being Crafted')], default='created'),
        ),
    ]
