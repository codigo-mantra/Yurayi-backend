# Generated by Django 5.2.4 on 2025-07-16 22:55

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('memory_room', '0005_memoryroomdetail_occupied_storage_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='memoryroommediafile',
            name='s3_key',
            field=models.CharField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name='memoryroommediafile',
            name='file_type',
            field=models.CharField(choices=[('image', 'Image'), ('video', 'Video'), ('audio', 'Audio'), ('document', 'Document'), ('other', 'Other')], default='other', max_length=20, verbose_name='File Type'),
        ),
        migrations.AlterField(
            model_name='timecapsoulmediafile',
            name='file_type',
            field=models.CharField(choices=[('image', 'Image'), ('video', 'Video'), ('audio', 'Audio'), ('document', 'Document'), ('other', 'Other')], default='other', max_length=20, verbose_name='File Type'),
        ),
    ]
