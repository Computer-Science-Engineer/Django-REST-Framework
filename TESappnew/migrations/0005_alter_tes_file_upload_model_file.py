# Generated by Django 4.1.5 on 2023-03-02 05:33

import TESappnew.models
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('TESappnew', '0004_tes_file_upload_model'),
    ]

    operations = [
        migrations.AlterField(
            model_name='tes_file_upload_model',
            name='file',
            field=models.ImageField(upload_to=TESappnew.models.image_path),
        ),
    ]