# Generated by Django 5.2.4 on 2025-07-16 05:39

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('memory_room', '0004_memoryroommediafile_memory_room_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='memoryroomdetail',
            name='occupied_storage',
            field=models.CharField(blank=True, help_text='Storage used timecap-soul', null=True),
        ),
        migrations.AddField(
            model_name='memoryroommediafile',
            name='s3_url',
            field=models.URLField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='timecapsouldetail',
            name='occupied_storage',
            field=models.CharField(blank=True, help_text='Storage used timecap-soul', null=True),
        ),
        migrations.AddField(
            model_name='timecapsoulmediafile',
            name='s3_url',
            field=models.URLField(blank=True, null=True),
        ),
    ]
